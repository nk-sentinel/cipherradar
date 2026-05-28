package main

import (
	"crypto/rand"

	"github.com/tjfoc/gmsm/sm2"
)

// SM2 key generation (quantum-vulnerable)
// EXPECTED: SM2 | pke | | medium | quantum-vulnerable
func generateSM2() {
	priv, _ := sm2.GenerateKey(rand.Reader)
	_ = priv
}

// SM2 encryption (quantum-vulnerable)
// EXPECTED: SM2 | pke | | medium | quantum-vulnerable
func encryptSM2(pub *sm2.PublicKey, data []byte) {
	ciphertext, _ := sm2.Encrypt(pub, data, rand.Reader, sm2.C1C3C2)
	_ = ciphertext
}

// SM2 signature (quantum-vulnerable)
// EXPECTED: SM2 | signature | | medium | quantum-vulnerable
func signSM2(priv *sm2.PrivateKey, msg []byte) {
	r, s, _ := sm2.Sign(priv, msg)
	_, _ = r, s
}
