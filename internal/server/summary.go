package server

import (
	"fmt"
	"strings"

	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
)

// summarize builds the one-line text used for notifications and list titles.
func summarize(d sshwire.Details, c protocol.Context) string {
	switch d.Kind {
	case sshwire.KindUserauth:
		s := "SSH login as " + d.User
		switch {
		case c.SessionBind != nil && len(c.SessionBind.HostNames) > 0:
			s += " to " + c.SessionBind.HostNames[0]
		case c.Remote != "":
			s += " to " + c.Remote
		}
		if c.Action != "" {
			s += " (" + c.Action + ")"
		}
		return s
	case sshwire.KindSSHSig:
		var s string
		switch g := c.GitObject; {
		case g != nil && d.Namespace == "git":
			return fmt.Sprintf("Sign %s: %s", g.Type, truncate(g.Subject, 80))
		case d.Namespace == "git":
			s = "Sign git object"
		default:
			s = fmt.Sprintf("Sign data (namespace %q)", d.Namespace)
		}
		if c.Action != "" {
			s += " for " + c.Action
		}
		return s
	}
	return fmt.Sprintf("Sign %d bytes of unrecognized data", d.Length)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
