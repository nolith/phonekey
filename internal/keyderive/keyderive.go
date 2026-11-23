// Package keyderive mirrors the web app's derivation of an ed25519 key from a
// passkey's PRF output. The browser is the only real user of the derivation;
// this copy exists for the simulator and for tests that pin the JS output.
package keyderive

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"

	"golang.org/x/crypto/ssh"
)

// DefaultSalt is the PRF salt the web app passes to the passkey. Changing it
// (or using a different one per purpose) yields an independent key.
const DefaultSalt = "phonekey/ssh-ed25519/v1"

// HKDFInfo separates the SSH key from any other use of the PRF output.
const HKDFInfo = "phonekey ssh-ed25519 seed v1"

// Seed turns 32 bytes of PRF output into an RFC 8032 ed25519 seed.
func Seed(prf []byte) []byte {
	seed, err := hkdf.Key(sha256.New, prf, nil, HKDFInfo, ed25519.SeedSize)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	return seed
}

// Key derives the ed25519 private key for a PRF output.
func Key(prf []byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Seed(prf))
}

// AuthorizedKey formats an ed25519 public key as "ssh-ed25519 AAAA...".
func AuthorizedKey(pub ed25519.PublicKey) string {
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	b := ssh.MarshalAuthorizedKey(k)
	return string(b[:len(b)-1])
}
