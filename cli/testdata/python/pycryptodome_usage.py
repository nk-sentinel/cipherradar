from Crypto.Cipher import AES, DES, DES3, ARC4, ChaCha20_Poly1305
from Crypto.Hash import SHA256, BLAKE2b


def aes_gcm(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt_and_digest(plaintext)


def aes_ecb(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_cbc(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(plaintext)


def aes_siv(key, plaintext):
    cipher = AES.new(key, AES.MODE_SIV)
    return cipher.encrypt_and_digest(plaintext)


def des_ecb(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)


def des3_cbc(key, data):
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.encrypt(data)


def rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)


def chacha_poly(key, plaintext):
    cipher = ChaCha20_Poly1305.new(key=key)
    return cipher.encrypt_and_digest(plaintext)


def hash_sha256(data):
    return SHA256.new(data).hexdigest()


def hash_blake2b(data):
    return BLAKE2b.new(data=data, digest_bytes=32).hexdigest()
