//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
)

func expectKinds(t *testing.T, reqs []protocol.WebRequest, kinds ...string) {
	t.Helper()
	var got []string
	for _, r := range reqs {
		got = append(got, r.Details.Kind)
	}
	if !slices.Equal(got, kinds) {
		t.Fatalf("requests: got kinds %v, want %v", got, kinds)
	}
}

func TestGit(t *testing.T) {
	h := newHarness(t, 20*time.Second)
	work := filepath.Join(h.dir, "work")

	// Clone: one SSH login, bound to the container's host key.
	h.run(h.dir, "git", "clone", h.remote(), work)
	reqs := h.approver.take()
	expectKinds(t, reqs, sshwire.KindUserauth)
	c := reqs[0].Context
	if c.SessionBind == nil || !slices.Contains(c.SessionBind.HostNames, "[127.0.0.1]:"+h.port) {
		t.Fatalf("session bind: %+v", c.SessionBind)
	}
	if c.Action != "fetch from srv/repo" || reqs[0].Details.User != "git" {
		t.Fatalf("clone context: action %q, details %+v", c.Action, reqs[0].Details)
	}
	t.Logf("clone summary: %s", reqs[0].Summary)

	// Signed commit: one SSHSIG request whose commit content the agent read
	// from git's buffer file.
	os.WriteFile(filepath.Join(work, "README"), []byte("hello\n"), 0o644)
	h.run(work, "git", "add", "README")
	h.run(work, "git", "commit", "-S", "-m", "First signed commit", "-m", "With a body.")
	reqs = h.approver.take()
	expectKinds(t, reqs, sshwire.KindSSHSig)
	g := reqs[0].Context.GitObject
	if g == nil || g.Subject != "First signed commit" || g.Body != "With a body." || g.Author != "Test User <test@example.com>" {
		t.Fatalf("git object: %+v", g)
	}
	if reqs[0].Summary != "Sign commit: First signed commit" {
		t.Fatalf("summary %q", reqs[0].Summary)
	}
	out := h.run(work, "git", "verify-commit", "-v", "HEAD")
	if !strings.Contains(out, `Good "git" signature for test@example.com`) {
		t.Fatalf("verify-commit: %s", out)
	}

	// Push.
	h.run(work, "git", "push", "origin", "main")
	reqs = h.approver.take()
	expectKinds(t, reqs, sshwire.KindUserauth)
	if reqs[0].Context.Action != "push to srv/repo" {
		t.Fatalf("push action %q", reqs[0].Context.Action)
	}

	// A signed tag.
	h.run(work, "git", "tag", "-s", "v1", "-m", "Release one")
	reqs = h.approver.take()
	expectKinds(t, reqs, sshwire.KindSSHSig)
	if g := reqs[0].Context.GitObject; g == nil || g.Type != "tag" || g.Tag != "v1" || g.Subject != "Release one" {
		t.Fatalf("tag object: %+v", g)
	}
	h.run(work, "git", "verify-tag", "v1")

	// Denied on the phone: the push fails.
	h.approver.setPolicy("deny")
	os.WriteFile(filepath.Join(work, "README"), []byte("denied\n"), 0o644)
	h.run(work, "git", "commit", "-am", "unsigned")
	h.runFail(work, "git", "push", "origin", "main")
	expectKinds(t, h.approver.take(), sshwire.KindUserauth)

	// A rebase that re-signs several commits asks once per commit, all from
	// one git process, so they share a grant scope.
	h.approver.setPolicy("approve")
	for _, msg := range []string{"two", "three"} {
		os.WriteFile(filepath.Join(work, msg), []byte(msg), 0o644)
		h.run(work, "git", "add", msg)
		h.run(work, "git", "commit", "-m", msg)
	}
	h.run(work, "git", "rebase", "--force-rebase", "--gpg-sign", "HEAD~3")
	reqs = h.approver.take()
	expectKinds(t, reqs, sshwire.KindSSHSig, sshwire.KindSSHSig, sshwire.KindSSHSig)
	if s := reqs[0].Context.Scope; s == "" || reqs[1].Context.Scope != s || reqs[2].Context.Scope != s {
		t.Fatalf("rebase scopes differ: %q %q %q", reqs[0].Context.Scope, reqs[1].Context.Scope, reqs[2].Context.Scope)
	}
}

func TestCancelAndDeadline(t *testing.T) {
	h := newHarness(t, 3*time.Second)
	ctx := context.Background()

	// Ctrl-C while waiting: the request is cancelled, not left pending. A
	// terminal sends SIGINT to the whole foreground process group, which is
	// what reaches ssh.
	h.approver.setPolicy("ignore")
	cctx, cancel := context.WithCancel(ctx)
	cmd := h.command(cctx, h.dir, "git", "ls-remote", h.remote())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGINT) }
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		time.Sleep(50 * time.Millisecond)
		h.approver.mu.Lock()
		if len(h.approver.log) > 0 {
			id = h.approver.log[0].ID
		}
		h.approver.mu.Unlock()
	}
	if id == "" {
		t.Fatal("request never arrived")
	}
	cancel()
	cmd.Wait()
	waitStatus(t, h, id, protocol.StatusCancelled)
	h.approver.take()

	// Nobody answers: the agent gives up at its deadline.
	start := time.Now()
	h.runFail(h.dir, "git", "ls-remote", h.remote())
	if d := time.Since(start); d < 2900*time.Millisecond || d > 10*time.Second {
		t.Fatalf("deadline took %s", d)
	}
	reqs := h.approver.take()
	expectKinds(t, reqs, sshwire.KindUserauth)
	waitStatus(t, h, reqs[0].ID, protocol.StatusCancelled, protocol.StatusExpired)
}

func waitStatus(t *testing.T, h *harness, id string, want ...string) {
	t.Helper()
	var last string
	for i := 0; i < 100; i++ {
		r, err := h.store.Request(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		last = r.Status
		if slices.Contains(want, last) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("request %s: status %s, want %v", id, last, want)
}

func TestJJ(t *testing.T) {
	need(t, "jj")
	h := newHarness(t, 20*time.Second)
	work := filepath.Join(h.dir, "jjwork")
	os.WriteFile(filepath.Join(h.dir, "jj.toml"), []byte(`
[user]
name = "Test User"
email = "test@example.com"

[ui]
paginate = "never"

[signing]
behavior = "drop"
backend = "ssh"
key = "`+h.pubFile+`"

[signing.backends.ssh]
allowed-signers = "`+filepath.Join(h.dir, "allowed_signers")+`"
program = "`+keygenShim(t)+`"

[revsets]
git-sign-on-push = "~signed() & mine()"
`), 0o644)

	// jj git clone logs in twice (fetch, then a remote HEAD lookup).
	h.run(h.dir, "jj", "git", "clone", h.remote(), work)
	for _, r := range h.approver.take() {
		if r.Details.Kind != sshwire.KindUserauth {
			t.Fatalf("clone: unexpected %s request", r.Details.Kind)
		}
		t.Logf("jj clone: %s", r.Summary)
	}

	// Two commits, signed when pushed: jj signs each (through the
	// phonekey-keygen shim, so the agent can read the commit), then logs in.
	for _, msg := range []string{"jj one", "jj two"} {
		os.WriteFile(filepath.Join(work, strings.ReplaceAll(msg, " ", "-")), []byte(msg), 0o644)
		h.run(work, "jj", "commit", "-m", msg)
	}
	if reqs := h.approver.take(); len(reqs) != 0 {
		t.Fatalf("commits signed before push: %d requests", len(reqs))
	}
	h.run(work, "jj", "bookmark", "create", "main", "-r", "@-")
	h.run(work, "jj", "git", "push", "--bookmark", "main")
	reqs := h.approver.take()
	expectKinds(t, reqs, sshwire.KindSSHSig, sshwire.KindSSHSig, sshwire.KindUserauth)
	for _, r := range reqs {
		if r.Context.Scope != reqs[0].Context.Scope {
			t.Fatalf("jj git push requests don't share a scope: %q vs %q", r.Context.Scope, reqs[0].Context.Scope)
		}
	}
	if !strings.HasPrefix(reqs[0].Context.Action, "jj git push") {
		t.Fatalf("jj action %q", reqs[0].Context.Action)
	}
	for _, r := range reqs[:2] {
		if len(r.Context.GitObject.ChangeID) != 32 {
			t.Fatalf("jj commit without a change id: %+v", r.Context.GitObject)
		}
	}
	subjects := []string{reqs[0].Context.GitObject.Subject, reqs[1].Context.GitObject.Subject}
	slices.Sort(subjects)
	if !slices.Equal(subjects, []string{"jj one", "jj two"}) {
		t.Fatalf("jj commit subjects %v", subjects)
	}
	var procs []string
	for _, p := range reqs[0].Context.Processes {
		procs = append(procs, p.Command)
	}
	if !slices.Equal(procs, []string{"ssh-keygen", "phonekey-keygen", "jj", "e2e.test"}) {
		t.Fatalf("process context %v", procs)
	}
	t.Logf("jj push summaries: %q, %q, %q", reqs[0].Summary, reqs[1].Summary, reqs[2].Summary)

	// The pushed commits verify with plain git on a fresh clone.
	check := filepath.Join(h.dir, "check")
	h.run(h.dir, "git", "clone", h.remote(), check)
	h.approver.take()
	for _, rev := range []string{"HEAD", "HEAD~1"} {
		out := h.run(check, "git", "verify-commit", "-v", rev)
		if !strings.Contains(out, `Good "git" signature for test@example.com`) {
			t.Fatalf("verify %s: %s", rev, out)
		}
	}
	out := h.run(work, "jj", "log", "-r", "main", "--no-graph", "-T", `if(signature, signature.status(), "unsigned")`)
	if strings.TrimSpace(out) != "good" {
		t.Fatalf("jj signature status: %q", out)
	}
}

// keygenShim builds cmd/phonekey-keygen for jj to use as its ssh program.
func keygenShim(t *testing.T) string {
	bin := filepath.Join(t.TempDir(), "phonekey-keygen")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/phonekey-keygen")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building phonekey-keygen: %v\n%s", err, out)
	}
	return bin
}
