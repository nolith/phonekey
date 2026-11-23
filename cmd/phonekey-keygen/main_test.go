package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentSocket(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	t.Run("no agent", func(t *testing.T) {
		if s := agentSocket(); s != "" {
			t.Fatalf("got %q without an agent", s)
		}
	})

	ln, err := net.Listen("unix", filepath.Join(dir, "phonekey-agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Run("agent listening", func(t *testing.T) {
		if s := agentSocket(); s != filepath.Join(dir, "phonekey-agent.sock") {
			t.Fatalf("got %q", s)
		}
	})
	t.Run("explicit socket", func(t *testing.T) {
		t.Setenv("PHONEKEY_SOCKET", "/elsewhere.sock")
		if s := agentSocket(); s != "/elsewhere.sock" {
			t.Fatalf("got %q", s)
		}
	})
	t.Run("opted out", func(t *testing.T) {
		t.Setenv("PHONEKEY_SOCKET", "")
		if s := agentSocket(); s != "" {
			t.Fatalf("got %q, want SSH_AUTH_SOCK left alone", s)
		}
	})
}

func TestSignsStdin(t *testing.T) {
	cases := map[string]bool{
		"-Y sign -f key.pub -n git":        true,
		"-Y sign -f key.pub -n git file":   false,
		"-Y verify -f allowed -I x -n git": false,
		"-Y sign -U -f key.pub -n git":     true,
		"-Y sign -f key.pub -n git -X":     false,
	}
	for args, want := range cases {
		if got := signsStdin(splitArgs(args)); got != want {
			t.Errorf("%q: got %v, want %v", args, got, want)
		}
	}
}

func splitArgs(s string) []string { return strings.Fields(s) }
