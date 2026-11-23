package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"phonekey/internal/sshwire"
)

func serveUnix(t *testing.T, path string, serve func(net.Conn)) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
}

func TestUpstreamAndBindPolicy(t *testing.T) {
	dir := t.TempDir()

	// An ordinary agent holding one key stands in for a forwarded 1Password agent.
	_, upPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyring := sshagent.NewKeyring()
	keyring.Add(sshagent.AddedKey{PrivateKey: upPriv, Comment: "upstream"})
	upSock := filepath.Join(dir, "up.sock")
	serveUnix(t, upSock, func(c net.Conn) { sshagent.ServeAgent(keyring, c); c.Close() })

	phonePub, _, _ := ed25519.GenerateKey(rand.Reader)
	phoneKey, _ := ssh.NewPublicKey(phonePub)
	a := New(Config{
		Keys:               func() []ssh.PublicKey { return []ssh.PublicKey{phoneKey} },
		Upstream:           upSock,
		RequireSessionBind: true,
		Backend:            &Backend{URL: "http://127.0.0.1:1", Token: "unused"},
	})
	sock := filepath.Join(dir, "phonekey.sock")
	serveUnix(t, sock, a.serveConn)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := sshagent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Comment != "phonekey" || keys[1].Comment != "upstream" {
		t.Fatalf("keys: %v", keys)
	}

	// Upstream keys sign through the upstream agent.
	upSigner, _ := ssh.NewSignerFromKey(upPriv)
	sig, err := client.Sign(upSigner.PublicKey(), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := upSigner.PublicKey().Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}

	// A userauth request for a session that was never bound is refused
	// before anything reaches the backend.
	userauth := ssh.Marshal(struct {
		Session []byte
		Msg     byte
		User    string
		Service string
		Method  string
		Sig     bool
		Alg     string
		Key     []byte
	}{[]byte("sid"), msgUserauthRequest, "git", "ssh-connection", "publickey", true, "ssh-ed25519", phoneKey.Marshal()})
	if _, err := client.Sign(phoneKey, userauth); err == nil || !strings.Contains(err.Error(), "failed to sign") {
		t.Fatalf("unbound userauth: %v", err)
	}
}

const msgUserauthRequest = 50

func TestSessionBindPolicy(t *testing.T) {
	hostA, _, _ := ed25519.GenerateKey(rand.Reader)
	hostB, _, _ := ed25519.GenerateKey(rand.Reader)
	keyA, _ := ssh.NewPublicKey(hostA)
	keyB, _ := ssh.NewPublicKey(hostB)
	// Agent forwarding: dev box -> A bound for forwarding, then A -> B.
	c := &connAgent{a: New(Config{RequireSessionBind: true}), binds: []*sshwire.SessionBind{
		{HostKey: keyA, SessionID: []byte("sid-A"), Forwarding: true},
		{HostKey: keyB, SessionID: []byte("sid-B")},
	}}
	sb, err := c.checkUserauth(&sshwire.Userauth{SessionID: []byte("sid-B")}, nil)
	if err != nil || !sb.Forwarding || sb.HostKeyFingerprint != ssh.FingerprintSHA256(keyB) {
		t.Fatalf("login to B over the forwarded agent: %+v, %v", sb, err)
	}
	if _, err := c.checkUserauth(&sshwire.Userauth{SessionID: []byte("sid-A")}, nil); err == nil {
		t.Fatal("signed userauth for an older binding")
	}
	c.binds = c.binds[:1]
	if _, err := c.checkUserauth(&sshwire.Userauth{SessionID: []byte("sid-A")}, nil); err == nil {
		t.Fatal("signed userauth for a forwarding-only binding")
	}
}

// A request of any kind on a connection carrying a forwarding binding comes
// from another host, whatever the local process details say.
func TestForwardedContext(t *testing.T) {
	host, _, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewPublicKey(host)
	c := &connAgent{a: New(Config{}), binds: []*sshwire.SessionBind{{HostKey: hostKey, SessionID: []byte("sid"), Forwarding: true}}}
	sig := append([]byte("SSHSIG"), ssh.Marshal(struct {
		NS, Reserved, Alg string
		Hash              []byte
	}{"git", "", "sha512", make([]byte, 64)})...)
	rc, err := c.requestContext(sig)
	if err != nil || !rc.Forwarded {
		t.Fatalf("forwarded SSHSIG request: %+v, %v", rc, err)
	}
	c.binds[0].Forwarding = false
	if rc, _ := c.requestContext(sig); rc.Forwarded {
		t.Fatal("local request marked forwarded")
	}
}
