import os
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESCCM,
    AESSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives import hashes


def aead_aesgcm(key, plaintext, aad):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(os.urandom(12), plaintext, aad)


def aead_aesccm(key, plaintext, aad):
    aesccm = AESCCM(key)
    return aesccm.encrypt(os.urandom(13), plaintext, aad)


def aead_aessiv(key, plaintext, aad):
    aessiv = AESSIV(key)
    return aessiv.encrypt(plaintext, [aad])


def aead_chacha(key, plaintext, aad):
    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(os.urandom(12), plaintext, aad)


def hash_sha512_224(data):
    h = hashes.SHA512_224()
    return h


def hash_sha512_256(data):
    h = hashes.SHA512_256()
    return h
