package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"phonekey/internal/agent"
)

func TestProgramStatus(t *testing.T) {
	var buf bytes.Buffer
	p := &programStatus{w: &buf}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	p.update(agent.Status{Waiting: []string{"jj commit", "ssh github.com"}})
	p.update(agent.Status{Last: "jj commit: signed"})
	p.failed(errors.New("line one\nline two"))
	p.clear()

	want := "\033]7501;state=blocked:kind=auth:msg=" + b64("approve on phone: ssh github.com (+1 more)") + ":id=phonekey:app=phonekey-agent\033\\" +
		"\033]7501;state=idle:msg=" + b64("jj commit: signed") + ":id=phonekey:app=phonekey-agent\033\\" +
		"\033]7501;state=error:msg=" + b64("line one line two") + ":id=phonekey:app=phonekey-agent\033\\" +
		"\033]7501;state=clear:id=phonekey:app=phonekey-agent\033\\"
	if got := buf.String(); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}

	buf.Reset()
	p.idle(strings.Repeat("é", maxMsg))
	text, _ := strings.CutPrefix(buf.String(), "\033]7501;state=idle:msg=")
	text, _, _ = strings.Cut(text, ":")
	dec, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(dec) > maxMsg || !strings.HasSuffix(string(dec), "…") {
		t.Fatalf("long msg: %d bytes, %v", len(dec), err)
	}

	// nil, as auto gives off a terminal, reports nothing.
	var off *programStatus
	off.update(agent.Status{Waiting: []string{"x"}})
}

func TestProgramStatusMode(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for mode, on := range map[string]bool{"auto": false, "on": true, "off": false} {
		p, err := newProgramStatus(mode, f)
		if err != nil || (p != nil) != on {
			t.Errorf("%s on a file: %v, %v", mode, p, err)
		}
	}
	if _, err := newProgramStatus("yes", f); err == nil {
		t.Error("yes: no error")
	}
}

// A report to a closed stdout must not kill the agent with SIGPIPE.
func TestProgramStatusBrokenPipe(t *testing.T) {
	if os.Getenv("PHONEKEY_TEST_BROKEN_PIPE") != "" {
		p, err := newProgramStatus("on", os.Stdout)
		if err != nil {
			os.Exit(2)
		}
		for range 10 {
			p.idle("nobody reads this")
		}
		os.Exit(0)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProgramStatusBrokenPipe$")
	cmd.Env = append(os.Environ(), "PHONEKEY_TEST_BROKEN_PIPE=1")
	cmd.Stdout = w
	err = cmd.Run()
	w.Close()
	if err != nil {
		t.Fatalf("agent died writing to a broken pipe: %v", err)
	}
}
