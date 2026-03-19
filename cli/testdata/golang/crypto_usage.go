package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
)

func encryptAES(key, plaintext []byte) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	gcm.Seal(nonce, nonce, plaintext, nil)
}

func badDES(key []byte) {
	block, _ := des.NewCipher(key)
	_ = block
}

func badMD5(data []byte) {
	hash := md5.Sum(data)
	_ = hash
}

func badSHA1(data []byte) {
	hash := sha1.Sum(data)
	_ = hash
}

func goodSHA256(data []byte) {
	hash := sha256.Sum256(data)
	_ = hash
}

func generateRSA() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

func badTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
}
