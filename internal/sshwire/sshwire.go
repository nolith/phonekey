// Package sshwire parses the payloads an ssh-agent is asked to sign and the
// session-bind@openssh.com extension.
package sshwire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	KindUserauth = "userauth"
	KindSSHSig   = "sshsig"
	KindUnknown  = "unknown"
)

const msgUserauthRequest = 50

var sshsigMagic = []byte("SSHSIG")

// Details is what can be learned from the signed bytes themselves. Unlike the
// context a dev box supplies, these fields are covered by the signature.
type Details struct {
	Kind string `json:"kind"`

	// userauth (RFC 4252 section 7)
	SessionID          string `json:"session_id,omitempty"`
	User               string `json:"user,omitempty"`
	Service            string `json:"service,omitempty"`
	Method             string `json:"method,omitempty"`
	Algorithm          string `json:"algorithm,omitempty"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`

	// SSHSIG (OpenSSH PROTOCOL.sshsig)
	Namespace     string `json:"namespace,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	Hash          string `json:"hash,omitempty"`

	Length int `json:"length"`
}

// Userauth is a parsed SSH_MSG_USERAUTH_REQUEST signature payload.
type Userauth struct {
	SessionID []byte
	User      string
	Service   string
	Method    string
	Algorithm string
	PublicKey []byte
	// HostKey is set for publickey-hostbound-v00@openssh.com requests.
	HostKey []byte
}

// SSHSig is a parsed SSHSIG signed-data blob.
type SSHSig struct {
	Namespace     string
	HashAlgorithm string
	Hash          []byte
}

type reader struct{ b []byte }

func (r *reader) str() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, errors.New("short read")
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(len(r.b)-4) < uint64(n) {
		return nil, errors.New("short string")
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, nil
}

func (r *reader) byte() (byte, error) {
	if len(r.b) < 1 {
		return 0, errors.New("short read")
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

// ParseUserauth parses data as a publickey userauth signature payload.
func ParseUserauth(data []byte) (*Userauth, error) {
	r := &reader{data}
	var u Userauth
	var err error
	if u.SessionID, err = r.str(); err != nil {
		return nil, err
	}
	if c, err := r.byte(); err != nil || c != msgUserauthRequest {
		return nil, errors.New("not a userauth request")
	}
	fields := []*string{&u.User, &u.Service, &u.Method}
	for _, f := range fields {
		s, err := r.str()
		if err != nil {
			return nil, err
		}
		*f = string(s)
	}
	if u.Method != "publickey" && u.Method != "publickey-hostbound-v00@openssh.com" {
		return nil, fmt.Errorf("unexpected userauth method %q", u.Method)
	}
	if c, err := r.byte(); err != nil || c != 1 {
		return nil, errors.New("userauth request without signature flag")
	}
	alg, err := r.str()
	if err != nil {
		return nil, err
	}
	u.Algorithm = string(alg)
	if u.PublicKey, err = r.str(); err != nil {
		return nil, err
	}
	if u.Method == "publickey-hostbound-v00@openssh.com" {
		if u.HostKey, err = r.str(); err != nil {
			return nil, err
		}
	}
	if len(r.b) != 0 {
		return nil, errors.New("trailing bytes after userauth request")
	}
	return &u, nil
}

// ParseSSHSig parses data as the blob ssh-keygen -Y sign asks an agent to sign.
func ParseSSHSig(data []byte) (*SSHSig, error) {
	if !bytes.HasPrefix(data, sshsigMagic) {
		return nil, errors.New("missing SSHSIG magic")
	}
	r := &reader{data[len(sshsigMagic):]}
	ns, err := r.str()
	if err != nil {
		return nil, err
	}
	if _, err := r.str(); err != nil { // reserved
		return nil, err
	}
	alg, err := r.str()
	if err != nil {
		return nil, err
	}
	h, err := r.str()
	if err != nil {
		return nil, err
	}
	if len(r.b) != 0 {
		return nil, errors.New("trailing bytes after SSHSIG blob")
	}
	return &SSHSig{Namespace: string(ns), HashAlgorithm: string(alg), Hash: h}, nil
}

// Parse classifies data and extracts what it can.
func Parse(data []byte) Details {
	d := Details{Kind: KindUnknown, Length: len(data)}
	if s, err := ParseSSHSig(data); err == nil {
		d.Kind = KindSSHSig
		d.Namespace = s.Namespace
		d.HashAlgorithm = s.HashAlgorithm
		d.Hash = hex.EncodeToString(s.Hash)
		return d
	}
	if u, err := ParseUserauth(data); err == nil {
		d.Kind = KindUserauth
		d.SessionID = hex.EncodeToString(u.SessionID)
		d.User = u.User
		d.Service = u.Service
		d.Method = u.Method
		d.Algorithm = u.Algorithm
		d.KeyFingerprint = fingerprintBlob(u.PublicKey)
		if u.HostKey != nil {
			d.HostKeyFingerprint = fingerprintBlob(u.HostKey)
		}
	}
	return d
}

func fingerprintBlob(blob []byte) string {
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(k)
}

// SessionBind is a verified session-bind@openssh.com extension request.
type SessionBind struct {
	HostKey    ssh.PublicKey
	SessionID  []byte
	Forwarding bool
}

// ParseSessionBind parses the extension contents and checks that the session
// identifier is signed by the host key.
func ParseSessionBind(contents []byte) (*SessionBind, error) {
	r := &reader{contents}
	hk, err := r.str()
	if err != nil {
		return nil, err
	}
	sid, err := r.str()
	if err != nil {
		return nil, err
	}
	sigBlob, err := r.str()
	if err != nil {
		return nil, err
	}
	fwd, err := r.byte()
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.ParsePublicKey(hk)
	if err != nil {
		return nil, fmt.Errorf("session-bind host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBlob, &sig); err != nil {
		return nil, fmt.Errorf("session-bind signature: %w", err)
	}
	if err := hostKey.Verify(sid, &sig); err != nil {
		return nil, fmt.Errorf("session-bind signature does not verify: %w", err)
	}
	return &SessionBind{HostKey: hostKey, SessionID: sid, Forwarding: fwd != 0}, nil
}
