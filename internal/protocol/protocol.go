// Package protocol holds the JSON types shared by phonekeyd, phonekey-agent
// and the simulator.
package protocol

import "phonekey/internal/sshwire"

// Request statuses.
const (
	StatusPending   = "pending"
	StatusSigned    = "signed"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusCancelled = "cancelled"
)

// Context is what the dev box tells the approver about a request. It helps a
// human decide but nothing in it is covered by the signature, so a
// compromised dev box can lie here.
type Context struct {
	Host      string    `json:"host,omitempty"`
	Processes []Process `json:"processes,omitempty"` // peer first, then ancestors
	// Scope identifies the process tree a request came from (e.g. one jj
	// invocation). Grants on the phone are limited to a scope.
	Scope string `json:"scope,omitempty"`
	// Action is a one-line guess at what's happening, e.g. "push to stancl/foo".
	Action      string       `json:"action,omitempty"`
	Remote      string       `json:"remote,omitempty"`
	SessionBind *SessionBind `json:"session_bind,omitempty"`
	GitObject   *GitObject   `json:"git_object,omitempty"`
}

type Process struct {
	PID     int      `json:"pid"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// SessionBind describes the session-bind@openssh.com binding the agent
// verified for a userauth request.
type SessionBind struct {
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	HostNames          []string `json:"host_names,omitempty"`
	Forwarding         bool     `json:"forwarding,omitempty"`
}

// GitObject is a commit or tag the agent read from the file ssh-keygen was
// asked to sign, after checking its hash against the SSHSIG blob.
type GitObject struct {
	Type      string `json:"type"`
	Author    string `json:"author,omitempty"`
	Committer string `json:"committer,omitempty"`
	Tagger    string `json:"tagger,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Body      string `json:"body,omitempty"`
	Parents   int    `json:"parents,omitempty"`
}

// CreateRequest is POSTed by the agent to /api/devbox/requests.
type CreateRequest struct {
	PublicKey  string  `json:"public_key"` // authorized_keys format
	Data       []byte  `json:"data"`
	Context    Context `json:"context"`
	TTLSeconds int     `json:"ttl_seconds,omitempty"`
}

type CreateResponse struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
}

// RequestState is returned by the agent's long-poll.
type RequestState struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Signature []byte `json:"signature,omitempty"` // raw 64-byte ed25519 signature
}

// WebRequest is a pending request as shown to the approval page.
type WebRequest struct {
	ID          string          `json:"id"`
	Devbox      string          `json:"devbox"`
	PublicKey   string          `json:"public_key"`
	Fingerprint string          `json:"fingerprint"`
	Data        []byte          `json:"data"`
	Details     sshwire.Details `json:"details"`
	Context     Context         `json:"context"`
	Summary     string          `json:"summary"`
	Status      string          `json:"status"`
	CreatedAt   int64           `json:"created_at"`
	ExpiresAt   int64           `json:"expires_at"`
}

// AuthMessage is what the page signs with the derived key to log in. The
// prefix can never begin a userauth payload or an SSHSIG blob, and phonekeyd
// refuses signing requests that are neither.
func AuthMessage(nonce string) []byte {
	return []byte("phonekey-auth-v1\n" + nonce)
}

type NonceResponse struct {
	Nonce string `json:"nonce"`
}

type LoginRequest struct {
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
	Signature []byte `json:"signature"`
}

type PairRequest struct {
	Code         string `json:"code"`
	Label        string `json:"label"`
	PublicKey    string `json:"public_key"`
	CredentialID string `json:"credential_id,omitempty"` // base64url
	Nonce        string `json:"nonce"`
	Signature    []byte `json:"signature"`
}

type SignatureSubmission struct {
	Signature []byte `json:"signature"`
	// Grant is set when the page signed without a fresh Face ID because the
	// request fell inside an open grant.
	Grant bool `json:"grant,omitempty"`
}

type WebKey struct {
	ID           int64  `json:"id"`
	PublicKey    string `json:"public_key"`
	Fingerprint  string `json:"fingerprint"`
	Label        string `json:"label"`
	CredentialID string `json:"credential_id,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

// WebConfig is what the page needs before it can do anything.
type WebConfig struct {
	RPID            string   `json:"rp_id,omitempty"` // empty: the page's hostname
	RPName          string   `json:"rp_name"`
	Salt            string   `json:"salt"`
	HKDFInfo        string   `json:"hkdf_info"`
	VAPIDPublicKey  string   `json:"vapid_public_key"`
	MaxGrantSeconds int      `json:"max_grant_seconds"`
	LoggedIn        bool     `json:"logged_in"`
	Keys            []WebKey `json:"keys,omitempty"`
}
