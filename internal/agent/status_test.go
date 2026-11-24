package agent

import (
	"errors"
	"slices"
	"testing"

	"phonekey/internal/protocol"
)

func TestStatus(t *testing.T) {
	var got []Status
	a := New(Config{Status: func(st Status) { got = append(got, st) }})

	push := a.begin(protocol.Context{Remote: "github.com", Action: "push to stancl/foo"})
	commit := a.begin(protocol.Context{Action: "jj commit"})
	a.end(push, nil)
	a.end(commit, errors.New("request x denied"))
	a.end(commit, nil) // already ended: no report

	want := []Status{
		{Waiting: []string{"ssh github.com: push to stancl/foo"}},
		{Waiting: []string{"ssh github.com: push to stancl/foo", "jj commit"}},
		{Waiting: []string{"jj commit"}, Last: "ssh github.com: push to stancl/foo: signed"},
		{Last: "jj commit: request x denied"},
	}
	if !slices.EqualFunc(got, want, func(a, b Status) bool {
		return a.Last == b.Last && slices.Equal(a.Waiting, b.Waiting)
	}) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestDescribe(t *testing.T) {
	for _, tc := range []struct {
		rc   protocol.Context
		want string
	}{
		{protocol.Context{}, "signature"},
		{protocol.Context{SessionBind: &protocol.SessionBind{HostNames: []string{"nucchero"}}}, "ssh nucchero"},
		{protocol.Context{Remote: "example.com:2222", Forwarded: true}, "ssh example.com:2222 (forwarded)"},
	} {
		if got := describe(tc.rc); got != tc.want {
			t.Errorf("describe(%+v) = %q, want %q", tc.rc, got, tc.want)
		}
	}
}
