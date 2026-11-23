package keyderive

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The web app's derivation must produce the same key; the browser e2e test
// checks ed25519.js against Seed for the same input.
func TestSeedIsStable(t *testing.T) {
	prf := bytes.Repeat([]byte{0x42}, 32)
	got := hex.EncodeToString(Seed(prf))
	const want = "37df986c47af038c0602b7f9c4418a0f752c9fa52ea4691026f4a1b0e3a73451"
	if got != want {
		t.Fatalf("Seed changed: got %s, want %s (changing it changes every derived key)", got, want)
	}
}
