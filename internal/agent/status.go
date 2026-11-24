package agent

import (
	"fmt"
	"slices"
	"strings"

	"phonekey/internal/protocol"
)

// Status is the state of the agent's phone requests, for Config.Status.
type Status struct {
	// Waiting lists the requests awaiting approval, oldest first.
	Waiting []string
	// Last is how the latest request ended, e.g. "jj commit: signed";
	// empty until one does.
	Last string
}

type pending struct {
	id   uint64
	what string
}

// begin records a waiting request and returns its token for end.
func (a *Agent) begin(rc protocol.Context) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	a.waiting = append(a.waiting, pending{a.next, describe(rc)})
	a.report()
	return a.next
}

// end records how a request ended; nil err means signed.
func (a *Agent) end(id uint64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	i := slices.IndexFunc(a.waiting, func(p pending) bool { return p.id == id })
	if i < 0 {
		return
	}
	what := a.waiting[i].what
	a.waiting = slices.Delete(a.waiting, i, i+1)
	if err != nil {
		a.last = fmt.Sprintf("%s: %v", what, err)
	} else {
		a.last = what + ": signed"
	}
	a.report()
}

// report sends the current status. The caller holds a.mu, so reports
// stay in order.
func (a *Agent) report() {
	if a.cfg.Status == nil {
		return
	}
	st := Status{Last: a.last}
	for _, p := range a.waiting {
		st.Waiting = append(st.Waiting, p.what)
	}
	a.cfg.Status(st)
}

// describe names a request, e.g. "ssh github.com: push to stancl/foo" or
// "jj commit".
func describe(rc protocol.Context) string {
	remote := rc.Remote
	if remote == "" && rc.SessionBind != nil && len(rc.SessionBind.HostNames) > 0 {
		remote = rc.SessionBind.HostNames[0]
	}
	var parts []string
	if remote != "" {
		parts = append(parts, "ssh "+remote)
	}
	if rc.Action != "" {
		parts = append(parts, rc.Action)
	}
	what := strings.Join(parts, ": ")
	if what == "" {
		what = "signature"
	}
	if rc.Forwarded {
		what += " (forwarded)"
	}
	return what
}
