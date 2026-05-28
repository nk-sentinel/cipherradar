package main

import (
	"crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	bls12381 "github.com/kilic/bls12-381"
)

// Schnorr (BIP-340 / Taproot) signatures — quantum-vulnerable.
func signSchnorr(priv *btcecPrivKey, msg []byte) {
	// EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
	sig, _ := schnorr.Sign(priv, msg)
	_ = sig
}

func verifySchnorr(sigBytes, msg, pub []byte) {
	// EXPECTED: Schnorr | signature | schnorr | info | quantum-vulnerable
	sig, _ := schnorr.ParseSignature(sigBytes)
	_ = sig
}

// BLS12-381 pairing-based signatures — quantum-vulnerable.
func blsGroup() {
	// EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
	g1 := bls12381.NewG1()
	_ = g1
	// EXPECTED: BLS12-381 | signature | bls | info | quantum-vulnerable
	g2 := bls12381.NewG2()
	_ = g2
}

// placeholder type so the fixture parses standalone.
type btcecPrivKey struct{}

func main() {
	_ = rand.Reader
}
