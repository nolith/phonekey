// Package agent implements phonekey-agent: an ssh-agent whose keys live on
// the phone. Each signature request is queued on phonekeyd and the agent
// waits for the approval page to post the signature back.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"phonekey/internal/protocol"
	"phonekey/internal/sshwire"
)

type Config struct {
	Backend *Backend
	// Keys returns the phone keys to offer. It's called on every List and
	// Sign, so it can reflect a refreshed key set.
	Keys func() []ssh.PublicKey
	// Deadline bounds how long a signature request waits for approval. The
	// ssh-agent protocol has no timeout of its own.
	Deadline time.Duration
	// Upstream is the socket of another agent (e.g. a forwarded 1Password
	// agent) whose keys are offered alongside the phone keys.
	Upstream string
	// RequireSessionBind refuses userauth signatures for sessions that
	// weren't bound with session-bind@openssh.com on the same connection.
	RequireSessionBind bool
	// RequireKnownHost refuses userauth signatures for hosts whose key isn't
	// in one of KnownHosts.
	RequireKnownHost bool
	KnownHosts       []string
	Hostname         string
	Logger           *slog.Logger
}

type Agent struct {
	cfg Config
	log *slog.Logger
}

func New(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Deadline == 0 {
		cfg.Deadline = 90 * time.Second
	}
	return &Agent{cfg: cfg, log: cfg.Logger}
}

// Serve accepts agent connections until the listener is closed.
func (a *Agent) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go a.serveConn(c)
	}
}

func (a *Agent) serveConn(c net.Conn) {
	defer c.Close()
	// ServeAgent handles one request at a time and doesn't read while a
	// handler runs. Reading the socket ourselves lets a blocked Sign notice
	// that the client went away (Ctrl-C) and cancel the phone request.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, c)
		cancel()
		pw.CloseWithError(err)
	}()
	ca := &connAgent{a: a, ctx: ctx, pid: peerPID(c)}
	err := sshagent.ServeAgent(ca, struct {
		io.Reader
		io.Writer
	}{pr, c})
	if err != nil && !errors.Is(err, io.EOF) {
		a.log.Debug("agent connection ended", "err", err)
	}
}

var errReadOnly = errors.New("phonekey-agent holds no private keys")

// connAgent is the per-connection agent state: session bindings are scoped
// to a connection, as in OpenSSH's ssh-agent.
type connAgent struct {
	a     *Agent
	ctx   context.Context
	pid   int
	binds []*sshwire.SessionBind

	mu       sync.Mutex
	upstream sshagent.ExtendedAgent
	upConn   net.Conn
}

// up returns the upstream agent, connecting on first use, with timeout as
// the deadline for the next call. The upstream connection lives as long as
// the client's.
func (c *connAgent) up(timeout time.Duration) sshagent.ExtendedAgent {
	if c.a.cfg.Upstream == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upstream == nil {
		conn, err := net.DialTimeout("unix", c.a.cfg.Upstream, 2*time.Second)
		if err != nil {
			c.a.log.Debug("upstream agent unavailable", "err", err)
			return nil
		}
		context.AfterFunc(c.ctx, func() { conn.Close() })
		c.upConn = conn
		c.upstream = sshagent.NewClient(conn)
	}
	c.upConn.SetDeadline(time.Now().Add(timeout))
	return c.upstream
}

const upstreamTimeout = 10 * time.Second

func (c *connAgent) phoneKey(key ssh.PublicKey) bool {
	want := key.Marshal()
	for _, k := range c.a.cfg.Keys() {
		if bytes.Equal(k.Marshal(), want) {
			return true
		}
	}
	return false
}

func (c *connAgent) List() ([]*sshagent.Key, error) {
	var keys []*sshagent.Key
	for _, k := range c.a.cfg.Keys() {
		keys = append(keys, &sshagent.Key{Format: k.Type(), Blob: k.Marshal(), Comment: "phonekey"})
	}
	if up := c.up(upstreamTimeout); up != nil {
		upKeys, err := up.List()
		if err != nil {
			c.a.log.Warn("upstream agent list failed", "err", err)
		}
		for _, k := range upKeys {
			if !c.phoneKey(k) {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

func (c *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	if c.phoneKey(key) {
		sig, err := c.phoneSign(key, data)
		if err != nil {
			c.a.log.Warn("signature refused", "key", ssh.FingerprintSHA256(key), "err", err)
		}
		return sig, err
	}
	// The upstream agent may itself be waiting for a person to approve.
	if up := c.up(c.a.cfg.Deadline); up != nil {
		return up.SignWithFlags(key, data, flags)
	}
	return nil, fmt.Errorf("unknown key %s", ssh.FingerprintSHA256(key))
}

func (c *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "session-bind@openssh.com" {
		b, err := sshwire.ParseSessionBind(contents)
		if err != nil {
			c.a.log.Warn("rejected session-bind", "err", err)
			return nil, err
		}
		if len(c.binds) >= maxBinds {
			return nil, errors.New("too many session bindings on one connection")
		}
		c.binds = append(c.binds, b)
		if up := c.up(upstreamTimeout); up != nil {
			up.Extension(extensionType, contents)
		}
		return nil, nil
	}
	if up := c.up(upstreamTimeout); up != nil {
		return up.Extension(extensionType, contents)
	}
	return nil, sshagent.ErrExtensionUnsupported
}

func (c *connAgent) Add(sshagent.AddedKey) error    { return errReadOnly }
func (c *connAgent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (c *connAgent) RemoveAll() error               { return errReadOnly }
func (c *connAgent) Lock([]byte) error              { return errReadOnly }
func (c *connAgent) Unlock([]byte) error            { return errReadOnly }
func (c *connAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }

// maxBinds caps session bindings per connection: one per hop of agent
// forwarding.
const maxBinds = 16

// checkUserauth applies the session-bind policy and returns what the binding
// tells us about the server. As in OpenSSH's ssh-agent, once a connection has
// bindings, userauth is only signed for the most recent one, and not when
// that binding was made for forwarding the agent onward.
func (c *connAgent) checkUserauth(u *sshwire.Userauth, chain []proc) (*protocol.SessionBind, error) {
	if len(c.binds) == 0 {
		if c.a.cfg.RequireSessionBind {
			return nil, errors.New("userauth for a session that wasn't bound with session-bind@openssh.com")
		}
		return nil, nil
	}
	bind := c.binds[len(c.binds)-1]
	if !bytes.Equal(bind.SessionID, u.SessionID) {
		return nil, errors.New("userauth isn't for the session most recently bound on this connection")
	}
	if bind.Forwarding {
		return nil, errors.New("userauth for a session bound only to forward the agent")
	}
	forwarded := false
	for _, b := range c.binds {
		forwarded = forwarded || b.Forwarding
	}
	if u.HostKey != nil && !bytes.Equal(u.HostKey, bind.HostKey.Marshal()) {
		return nil, errors.New("host key in userauth request doesn't match the session binding")
	}
	var candidates []string
	if len(chain) > 0 && chain[0].comm == "ssh" {
		dest, port, _ := parseSSHArgs(chain[0].args)
		candidates = hostCandidates(dest, port)
	}
	names, known := hostNames(c.a.cfg.KnownHosts, bind.HostKey, candidates)
	if c.a.cfg.RequireKnownHost && !known {
		return nil, fmt.Errorf("host key %s is not in known_hosts", ssh.FingerprintSHA256(bind.HostKey))
	}
	return &protocol.SessionBind{
		HostKeyFingerprint: ssh.FingerprintSHA256(bind.HostKey),
		HostNames:          names,
		Forwarding:         forwarded,
	}, nil
}

// requestContext describes a signature request for the approver, and
// applies the session-bind policy to logins.
func (c *connAgent) requestContext(data []byte) (protocol.Context, error) {
	var chain []proc
	if c.pid > 0 {
		chain = processChain(c.pid)
	}
	rc := buildContext(c.a.cfg.Hostname, chain, data)
	for _, b := range c.binds {
		rc.Forwarded = rc.Forwarded || b.Forwarding
	}
	if u, err := sshwire.ParseUserauth(data); err == nil {
		sb, err := c.checkUserauth(u, chain)
		if err != nil {
			return rc, err
		}
		rc.SessionBind = sb
	}
	return rc, nil
}

func (c *connAgent) phoneSign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	rc, err := c.requestContext(data)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(c.ctx, c.a.cfg.Deadline)
	defer cancel()
	b := c.a.cfg.Backend
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	created, err := b.Create(ctx, protocol.CreateRequest{
		PublicKey:  authorized,
		Data:       data,
		Context:    rc,
		TTLSeconds: int(c.a.cfg.Deadline.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	c.a.log.Info("waiting for approval", "id", created.ID, "action", rc.Action, "remote", rc.Remote)
	st, err := b.Wait(ctx, created.ID)
	if err != nil {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		b.Cancel(cctx, created.ID)
		if c.ctx.Err() != nil {
			return nil, fmt.Errorf("request %s cancelled: client disconnected", created.ID)
		}
		return nil, fmt.Errorf("request %s: no approval within %s", created.ID, c.a.cfg.Deadline)
	}
	if st.Status != protocol.StatusSigned {
		return nil, fmt.Errorf("request %s %s", created.ID, st.Status)
	}
	sig := &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: st.Signature}
	if err := key.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("request %s: backend returned a signature that doesn't verify: %w", created.ID, err)
	}
	c.a.log.Info("signed", "id", created.ID)
	return sig, nil
}
