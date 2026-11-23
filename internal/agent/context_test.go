package agent

import (
	"crypto/sha512"
	"syscall"
	"time"

	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"os"
	"path/filepath"
	"phonekey/internal/protocol"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseSSHArgs(t *testing.T) {
	cases := []struct {
		args              []string
		dest, port, first string
	}{
		{[]string{"ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-receive-pack 'stancl/foo.git'"}, "git@github.com", "", "git-receive-pack 'stancl/foo.git'"},
		{[]string{"/usr/bin/ssh", "-4vp2222", "git@host", "git-upload-pack", "'/srv/r.git'"}, "git@host", "2222", "git-upload-pack"},
		{[]string{"ssh", "-p", "22", "-F/dev/null", "-l", "git", "host"}, "host", "22", ""},
		{[]string{"ssh", "--", "host", "ls"}, "host", "", "ls"},
	}
	for _, c := range cases {
		dest, port, cmd := parseSSHArgs(c.args)
		first := ""
		if len(cmd) > 0 {
			first = cmd[0]
		}
		if dest != c.dest || port != c.port || first != c.first {
			t.Errorf("%v: got %q %q %q", c.args, dest, port, first)
		}
	}
}

func TestGitAction(t *testing.T) {
	cases := map[string][]string{
		"push to stancl/foo": {"git-receive-pack 'stancl/foo.git'"},
		"fetch from srv/r":   {"git-upload-pack", "'/srv/r.git'"},
		"run uptime":         {"uptime"},
		"":                   nil,
	}
	for want, cmd := range cases {
		if got := gitAction(cmd); got != want {
			t.Errorf("%v: got %q want %q", cmd, got, want)
		}
	}
}

func TestScope(t *testing.T) {
	chain := []proc{
		{pid: 30, comm: "ssh-keygen", start: "3"},
		{pid: 20, comm: "jj", start: "2"},
		{pid: 10, comm: "bash", start: "1"},
		{pid: 5, comm: "jj", start: "0"},
	}
	if got := scope(chain); got != "20:2" {
		t.Fatalf("scope = %q", got)
	}
	if got := scope(chain[:1]); got != "30:3" {
		t.Fatalf("lone peer scope = %q", got)
	}
}

func TestParseGitObject(t *testing.T) {
	commit := "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent a\nparent b\n" +
		"author Ada <ada@example.com> 1700000000 +0100\ncommitter Bob <bob@example.com> 1700000001 +0000\n" +
		"change-id pwsrmprsornovmzvounuvnylntqlnuwt\n\n" +
		"Merge things\n\nLonger explanation.\n"
	g := parseGitObject([]byte(commit))
	want := GitObjectFields{"commit", "Ada <ada@example.com>", "Bob <bob@example.com>", "Merge things", "Longer explanation.", 2}
	got := GitObjectFields{g.Type, g.Author, g.Committer, g.Subject, g.Body, g.Parents}
	if got != want || g.ChangeID != "pwsrmprsornovmzvounuvnylntqlnuwt" {
		t.Fatalf("got %+v, change id %q", got, g.ChangeID)
	}
	tag := parseGitObject([]byte("object a\ntype commit\ntag v1.0\ntagger Ada <ada@example.com> 1 +0000\n\nRelease 1.0\n"))
	if tag.Type != "tag" || tag.Tag != "v1.0" || tag.Subject != "Release 1.0" {
		t.Fatalf("tag: %+v", tag)
	}
}

type GitObjectFields struct {
	Type, Author, Committer, Subject, Body string
	Parents                                int
}

func TestHostNames(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(pub)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ssh.NewPublicKey(other)
	line := string(ssh.MarshalAuthorizedKey(key))

	salt := []byte("0123456789abcdefghij")
	m := hmac.New(sha1.New, salt)
	m.Write([]byte("[secret.example]:2222"))
	hashed := "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" + base64.StdEncoding.EncodeToString(m.Sum(nil))

	file := filepath.Join(t.TempDir(), "known_hosts")
	content := "github.com,140.82.121.4 " + line + hashed + " " + line + "*.wild " + line +
		"@revoked revoked.example " + line + "other.example " + string(ssh.MarshalAuthorizedKey(otherKey))
	os.WriteFile(file, []byte(content), 0o600)

	names, known := hostNames([]string{file, "/nonexistent"}, key, hostCandidates("git@secret.example", "2222"))
	want := []string{"github.com", "140.82.121.4", "[secret.example]:2222"}
	if !known || !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v %v, want %v", names, known, want)
	}

	unknown, _, _ := ed25519.GenerateKey(rand.Reader)
	unknownKey, _ := ssh.NewPublicKey(unknown)
	if names, known := hostNames([]string{file}, unknownKey, nil); known || len(names) != 0 {
		t.Fatalf("unknown key matched: %v", names)
	}
}

func TestSignedGitObjectSkipsFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	h := sha512.Sum512(nil)
	data := append([]byte("SSHSIG"), ssh.Marshal(struct {
		NS, Reserved, Alg string
		Hash              []byte
	}{"git", "", "sha512", h[:]})...)
	done := make(chan *protocol.GitObject)
	go func() { done <- signedGitObject(proc{args: []string{"ssh-keygen", fifo}}, data) }()
	select {
	case g := <-done:
		if g != nil {
			t.Fatalf("parsed a FIFO: %+v", g)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
