//go:build e2e

// Package e2e runs phonekeyd, phonekey-agent and real OpenSSH, git and jj
// against a throwaway sshd container. Everything runs with a temporary HOME
// and explicit ssh/git/jj config, so the user's own setup is never read or
// written. Run with: go test -tags e2e ./e2e
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

const image = "phonekey-e2e-sshd"

type harness struct {
	t        *testing.T
	dir      string
	url      string
	store    *store.Store
	phone    *sim.Phone
	token    string
	sock     string
	pubFile  string
	port     string
	env      []string
	approver *approver
}

// approver plays the phone: it watches the event stream and applies policy
// to each new request.
type approver struct {
	mu     sync.Mutex
	policy string // "approve", "deny" or "ignore"
	seen   map[string]bool
	log    []protocol.WebRequest
}

func (a *approver) setPolicy(p string) {
	a.mu.Lock()
	a.policy = p
	a.mu.Unlock()
}

// take returns and clears the requests seen so far.
func (a *approver) take() []protocol.WebRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.log
	a.log = nil
	return out
}

func repoRoot(t *testing.T) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

func need(t *testing.T, tools ...string) {
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not in PATH (use the flake devshell)", tool)
		}
	}
}

func cmdOut(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newHarness(t *testing.T, deadline time.Duration) *harness {
	need(t, "docker", "ssh", "ssh-keygen", "git")
	ctx := context.Background()
	h := &harness{t: t, dir: t.TempDir()}

	// Backend
	st, err := store.Open(filepath.Join(h.dir, "phonekey.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h.store = st
	srv, err := server.New(ctx, st, server.Config{Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	h.url = ts.URL
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go srv.Sweep(sctx, 200*time.Millisecond)

	h.token, _ = st.AddDevbox(ctx, "e2e-devbox")
	code, _ := st.NewPairCode(ctx, time.Minute)
	h.phone = sim.New(ts.URL, bytes.Repeat([]byte{7}, 32))
	if err := h.phone.Pair(ctx, code, "e2e phone"); err != nil {
		t.Fatal(err)
	}
	h.pubFile = filepath.Join(h.dir, "phone.pub")
	os.WriteFile(h.pubFile, []byte(h.phone.PublicKey()+" phonekey\n"), 0o644)
	os.WriteFile(filepath.Join(h.dir, "allowed_signers"), []byte("test@example.com "+h.phone.PublicKey()+"\n"), 0o644)

	// sshd container
	cmdOut(t, "docker", "build", "-q", "-t", image, filepath.Join(repoRoot(t), "e2e", "sshd"))
	authKeys := filepath.Join(h.dir, "authorized_keys")
	os.WriteFile(authKeys, []byte(h.phone.PublicKey()+"\n"), 0o644)
	name := fmt.Sprintf("phonekey-e2e-%d", time.Now().UnixNano())
	cmdOut(t, "docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::22",
		"-v", authKeys+":/etc/ssh/authorized_keys/git:ro", image)
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("sshd logs:\n%s", logs)
		}
		exec.Command("docker", "rm", "-f", name).Run()
	})
	_, h.port, _ = net.SplitHostPort(cmdOut(t, "docker", "port", name, "22/tcp"))
	hostKey := cmdOut(t, "docker", "exec", name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	knownHosts := filepath.Join(h.dir, "known_hosts")
	os.WriteFile(knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%s %s\n", h.port, hostKey)), 0o644)
	waitTCP(t, "127.0.0.1:"+h.port)

	// Agent
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(h.phone.PublicKey()))
	h.sock = filepath.Join(h.dir, "agent.sock")
	ln, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	a := agent.New(agent.Config{
		Backend:            &agent.Backend{URL: ts.URL, Token: h.token},
		Keys:               func() []ssh.PublicKey { return []ssh.PublicKey{pk} },
		Deadline:           deadline,
		RequireSessionBind: true,
		RequireKnownHost:   true,
		KnownHosts:         []string{knownHosts},
		Hostname:           "e2e-host",
		Logger:             testLogger(t),
	})
	go a.Serve(ln)

	// Isolated environment for ssh, git and jj.
	home := filepath.Join(h.dir, "home")
	os.MkdirAll(home, 0o700)
	gitconfig := filepath.Join(h.dir, "gitconfig")
	os.WriteFile(gitconfig, []byte(fmt.Sprintf(`[user]
	name = Test User
	email = test@example.com
	signingkey = %s
[gpg]
	format = ssh
[gpg "ssh"]
	allowedSignersFile = %s
[init]
	defaultBranch = main
`, h.pubFile, filepath.Join(h.dir, "allowed_signers"))), 0o644)
	sshCmd := fmt.Sprintf("ssh -F /dev/null -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null "+
		"-o IdentitiesOnly=yes -i %s -o IdentityAgent=%s -o BatchMode=yes", knownHosts, h.pubFile, h.sock)
	h.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL=" + gitconfig,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_SSH_COMMAND=" + sshCmd,
		"SSH_AUTH_SOCK=" + h.sock,
		"JJ_CONFIG=" + filepath.Join(h.dir, "jj.toml"),
		"TZ=UTC",
	}

	// Phone
	h.approver = &approver{policy: "approve", seen: map[string]bool{}}
	wctx, wcancel := context.WithCancel(ctx)
	t.Cleanup(wcancel)
	if err := h.phone.Login(ctx); err != nil {
		t.Fatal(err)
	}
	go h.phone.Watch(wctx, func(reqs []protocol.WebRequest) error {
		a := h.approver
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, r := range reqs {
			if a.seen[r.ID] {
				continue
			}
			a.seen[r.ID] = true
			a.log = append(a.log, r)
			switch a.policy {
			case "approve":
				if err := h.phone.Approve(wctx, r); err != nil {
					t.Errorf("approve %s: %v", r.ID, err)
				}
			case "deny":
				h.phone.Deny(wctx, r.ID)
			}
		}
		return nil
	})
	return h
}

func (h *harness) remote() string {
	return fmt.Sprintf("ssh://git@127.0.0.1:%s/srv/repo.git", h.port)
}

func (h *harness) command(ctx context.Context, dir, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = h.env
	return cmd
}

func (h *harness) run(dir, name string, args ...string) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := h.command(ctx, dir, name, args...).CombinedOutput()
	if err != nil {
		h.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (h *harness) runFail(dir, name string, args ...string) string {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := h.command(ctx, dir, name, args...).CombinedOutput()
	if err == nil {
		h.t.Fatalf("%s %s: expected failure\n%s", name, strings.Join(args, " "), out)
	}
	return string(out)
}

func waitTCP(t *testing.T, addr string) {
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			buf := make([]byte, 4)
			c.SetReadDeadline(time.Now().Add(time.Second))
			_, err = io.ReadFull(c, buf)
			c.Close()
			if err == nil && string(buf) == "SSH-" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("sshd at %s didn't come up", addr)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func testLogger(t *testing.T) *slog.Logger {
	if os.Getenv("PHONEKEY_E2E_VERBOSE") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(testWriter{t}, nil))
}
