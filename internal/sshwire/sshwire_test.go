package sshwire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/ssh"
)

func str(b []byte) []byte { return ssh.Marshal(struct{ S []byte }{b}) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func newKey(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sp, signer
}

func TestParseUserauth(t *testing.T) {
	user, _ := newKey(t)
	host, _ := newKey(t)
	sid := []byte("0123456789abcdef0123456789abcdef")
	data := cat(str(sid), []byte{msgUserauthRequest}, str([]byte("git")), str([]byte("ssh-connection")),
		str([]byte("publickey-hostbound-v00@openssh.com")), []byte{1}, str([]byte("ssh-ed25519")),
		str(user.Marshal()), str(host.Marshal()))

	d := Parse(data)
	if d.Kind != KindUserauth || d.User != "git" || d.Service != "ssh-connection" {
		t.Fatalf("unexpected details %+v", d)
	}
	if d.KeyFingerprint != ssh.FingerprintSHA256(user) || d.HostKeyFingerprint != ssh.FingerprintSHA256(host) {
		t.Fatalf("fingerprints: %+v", d)
	}

	if _, err := ParseUserauth(append(data, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

func TestParseSSHSig(t *testing.T) {
	h := sha512.Sum512([]byte("tree abc\n"))
	data := cat([]byte("SSHSIG"), str([]byte("git")), str(nil), str([]byte("sha512")), str(h[:]))
	d := Parse(data)
	if d.Kind != KindSSHSig || d.Namespace != "git" || d.HashAlgorithm != "sha512" || len(d.Hash) != 128 {
		t.Fatalf("unexpected details %+v", d)
	}
	if Parse([]byte("phonekey-auth-v1\nnonce")).Kind != KindUnknown {
		t.Fatal("login message classified as signable")
	}
}

func TestSessionBind(t *testing.T) {
	host, signer := newKey(t)
	sid := []byte("session-id-bytes")
	sig, err := signer.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	contents := cat(str(host.Marshal()), str(sid), str(ssh.Marshal(sig)), []byte{0})
	b, err := ParseSessionBind(contents)
	if err != nil {
		t.Fatal(err)
	}
	if string(b.SessionID) != string(sid) || b.Forwarding {
		t.Fatalf("unexpected bind %+v", b)
	}

	forged := cat(str(host.Marshal()), str([]byte("another session")), str(ssh.Marshal(sig)), []byte{0})
	if _, err := ParseSessionBind(forged); err == nil {
		t.Fatal("forged session-bind accepted")
	}
}
