package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"

	"phonekey/internal/agent"
)

// programStatus reports the agent's state to its terminal with OSC 7501
// (https://www.superlogical.com/rex/docs/build/program-status): blocked
// while a request waits for the phone, idle otherwise. Other terminals
// ignore it.
//
// It reports under its own id: the root record belongs to the terminal's
// other programs, and a clear without id removes every record.
type programStatus struct {
	w io.Writer
}

// newProgramStatus returns nil for "off", or for "auto" when stdout isn't
// a terminal (e.g. the systemd journal).
func newProgramStatus(mode string, stdout *os.File) (*programStatus, error) {
	switch mode {
	case "on":
	case "off":
		return nil, nil
	case "auto":
		fi, err := stdout.Stat()
		if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
			return nil, nil
		}
	default:
		return nil, fmt.Errorf("--program-status must be auto, on or off, not %q", mode)
	}
	// Without a SIGPIPE handler, Go exits on a write to a closed stdout.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	return &programStatus{w: stdout}, nil
}

const (
	maxMsg    = 2048 // the protocol's limit on msg, decoded
	statusID  = "phonekey"
	statusApp = "phonekey-agent"
)

func (p *programStatus) send(pairs ...string) {
	if p == nil {
		return
	}
	fmt.Fprintf(p.w, "\033]7501;%s\033\\", strings.Join(append(pairs, "id="+statusID, "app="+statusApp), ":"))
}

func msg(text string) string {
	// The terminal drops a report whose msg has control characters.
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
	if len(text) > maxMsg {
		text = strings.ToValidUTF8(text[:maxMsg-len("…")], "") + "…"
	}
	return "msg=" + base64.StdEncoding.EncodeToString([]byte(text))
}

// idle reports that nothing waits for the phone.
func (p *programStatus) idle(text string) { p.send("state=idle", msg(text)) }

// update reports an agent.Status.
func (p *programStatus) update(st agent.Status) {
	switch n := len(st.Waiting); n {
	case 0:
		p.idle(st.Last)
	default:
		text := "approve on phone: " + st.Waiting[n-1]
		if n > 1 {
			text += fmt.Sprintf(" (+%d more)", n-1)
		}
		p.send("state=blocked", "kind=auth", msg(text))
	}
}

// failed reports the error the agent exits with.
func (p *programStatus) failed(err error) { p.send("state=error", msg(err.Error())) }

// clear removes the agent's record on a clean exit.
func (p *programStatus) clear() { p.send("state=clear") }
