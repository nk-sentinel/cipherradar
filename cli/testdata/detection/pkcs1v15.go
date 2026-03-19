package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func encryptPKCS1v15(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	// BAD: PKCS1v15 padding is vulnerable to padding oracle attacks
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

func signPKCS1v15(priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	// BAD: PKCS1v15 padding for signatures
	return rsa.SignPKCS1v15(rand.Reader, priv, 0, digest)
}

func encryptOAEP(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	// GOOD: OAEP padding
	return rsa.EncryptOAEP(nil, rand.Reader, pub, plaintext, nil)
}
