package main

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

func hashPassword(password []byte) {
	bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
}

func deriveKey(password, salt []byte) {
	argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func encryptChaCha(key []byte) {
	aead, _ := chacha20poly1305.New(key)
	_ = aead
}

func scryptKey(password, salt []byte) {
	scrypt.Key(password, salt, 32768, 8, 1, 32)
}
