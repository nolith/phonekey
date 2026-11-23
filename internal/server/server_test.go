package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"phonekey/internal/agent"
	"phonekey/internal/protocol"
	"phonekey/internal/server"
	"phonekey/internal/sim"
	"phonekey/internal/store"
)

type env struct {
	t       *testing.T
	url     string
	store   *store.Store
	phone   *sim.Phone
	backend *agent.Backend
}

func setup(t *testing.T, cfg server.Config) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(ctx, st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	sweepCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go srv.Sweep(sweepCtx, 100*time.Millisecond)

	token, err := st.AddDevbox(ctx, "devbox")
	if err != nil {
		t.Fatal(err)
	}
	code, err := st.NewPairCode(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	phone := sim.New(ts.URL, []byte("0123456789abcdef0123456789abcdef"))
	if err := phone.Pair(ctx, code, "test phone"); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, url: ts.URL, store: st, phone: phone, backend: &agent.Backend{URL: ts.URL, Token: token}}
}

func sshsigBlob(msg string) []byte {
	h := sha512.Sum512([]byte(msg))
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		NS, Reserved, Alg string
		Hash              []byte
	}{"git", "", "sha512", h[:]})...)
}

func TestApproveFlow(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	data := sshsigBlob("tree 123\n\nhello\n")
	created, err := e.backend.Create(ctx, protocol.CreateRequest{
		PublicKey: e.phone.PublicKey(),
		Data:      data,
		Context:   protocol.Context{GitObject: &protocol.GitObject{Type: "commit", Subject: "hello"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	pending, err := e.phone.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Summary != "Sign commit: hello" || pending[0].Details.Namespace != "git" {
		t.Fatalf("unexpected pending list: %+v", pending)
	}

	// The long-poll should wake up as soon as the phone signs.
	done := make(chan *protocol.RequestState)
	go func() {
		st, err := e.backend.Wait(ctx, created.ID)
		if err != nil {
			t.Error(err)
		}
		done <- st
	}()
	time.Sleep(100 * time.Millisecond)
	if err := e.phone.Approve(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-done:
		if st.Status != protocol.StatusSigned || !ed25519.Verify(e.phone.Key.Public().(ed25519.PublicKey), data, st.Signature) {
			t.Fatalf("bad result %+v", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll didn't return")
	}

	if err := e.phone.Approve(ctx, pending[0]); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("second approval should conflict, got %v", err)
	}
}

func TestBadSignatureRejected(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	created, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")})
	if err != nil {
		t.Fatal(err)
	}
	req := protocol.WebRequest{ID: created.ID, PublicKey: e.phone.PublicKey(), Data: sshsigBlob("something else")}
	if err := e.phone.Approve(ctx, req); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("want verification failure, got %v", err)
	}
}

func TestDenyCancelExpire(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	mk := func(ttl int) string {
		c, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x"), TTLSeconds: ttl})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	denied, cancelled, expired := mk(60), mk(60), mk(1)
	if err := e.phone.Deny(ctx, denied); err != nil {
		t.Fatal(err)
	}
	if err := e.backend.Cancel(ctx, cancelled); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{denied: "denied", cancelled: "cancelled", expired: "expired"} {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := e.backend.Wait(wctx, id)
		cancel()
		if err != nil || st.Status != want {
			t.Fatalf("%s: got %+v, %v; want %s", id, st, err, want)
		}
	}
	if p, _ := e.phone.Pending(ctx); len(p) != 0 {
		t.Fatalf("resolved requests still pending: %+v", p)
	}
}

func TestCreateValidation(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()
	other := sim.New(e.url, []byte("another passkey's prf output!!!!"))
	cases := map[string]protocol.CreateRequest{
		"unregistered key": {PublicKey: other.PublicKey(), Data: sshsigBlob("x")},
		"unknown data":     {PublicKey: e.phone.PublicKey(), Data: []byte("phonekey-auth-v1\nabc")},
		"bad key":          {PublicKey: "ssh-ed25519 nope", Data: sshsigBlob("x")},
	}
	for name, req := range cases {
		if _, err := e.backend.Create(ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := &agent.Backend{URL: e.url, Token: "pkd_wrong"}
	if _, err := bad.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")}); err == nil {
		t.Error("wrong token accepted")
	}
}

func TestWebAuth(t *testing.T) {
	e := setup(t, server.Config{})
	ctx := context.Background()

	// A key that wasn't paired can't log in, and a pairing code works once.
	other := sim.New(e.url, []byte("another passkey's prf output!!!!"))
	if err := other.Login(ctx); err == nil {
		t.Fatal("unpaired key logged in")
	}
	code, _ := e.store.NewPairCode(ctx, time.Minute)
	if err := other.Pair(ctx, code, "second"); err != nil {
		t.Fatal(err)
	}
	third := sim.New(e.url, []byte("a third passkey's prf output!!!!"))
	if err := third.Pair(ctx, code, "third"); err == nil {
		t.Fatal("pairing code reused")
	}

	// Cross-site writes are refused.
	req, _ := http.NewRequest(http.MethodPost, e.url+"/api/web/nonce", strings.NewReader("{}"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site nonce: %s", resp.Status)
	}
	req, _ = http.NewRequest(http.MethodPost, e.url+"/api/web/nonce", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin nonce: %s", resp.Status)
	}

	// Without a session, the pending list isn't readable.
	resp, _ = http.Get(e.url + "/api/web/requests")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %s", resp.Status)
	}
}

func TestEventsAndPush(t *testing.T) {
	var mu sync.Mutex
	var pushes []*http.Request
	pushSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pushes = append(pushes, r)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer pushSrv.Close()

	e := setup(t, server.Config{PushClient: pushSrv.Client()})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sub, _ := json.Marshal(map[string]any{
		"endpoint": pushSrv.URL + "/push/abc",
		"keys": map[string]string{
			// A valid P-256 point and auth secret, as a browser would send.
			"p256dh": "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM",
			"auth":   "tBHItJI5svbpez7KI4CCXg",
		},
	})
	if err := e.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.phone.Post(ctx, "/api/web/push/subscribe", json.RawMessage(sub), nil); err != nil {
		t.Fatal(err)
	}

	got := make(chan []protocol.WebRequest, 10)
	go e.phone.Watch(ctx, func(r []protocol.WebRequest) error {
		got <- r
		return nil
	})
	if first := <-got; len(first) != 0 {
		t.Fatalf("expected empty initial list, got %d", len(first))
	}
	if _, err := e.backend.Create(ctx, protocol.CreateRequest{PublicKey: e.phone.PublicKey(), Data: sshsigBlob("x")}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if len(r) != 1 {
			t.Fatalf("expected one request in stream, got %d", len(r))
		}
	case <-ctx.Done():
		t.Fatal("no event after request creation")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(pushes)
		mu.Unlock()
		if n > 0 {
			mu.Lock()
			p := pushes[0]
			mu.Unlock()
			if !strings.HasPrefix(p.Header.Get("Authorization"), "vapid t=") || p.Header.Get("Content-Encoding") != "aes128gcm" {
				t.Fatalf("push missing VAPID/encryption headers: %v", p.Header)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no push sent")
}
