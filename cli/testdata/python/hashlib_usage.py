import hashlib

def hash_password(password):
    md5_hash = hashlib.md5(password.encode())
    sha1_hash = hashlib.sha1(password.encode())
    sha256_hash = hashlib.sha256(password.encode())

    algo = "sha512"
    dynamic_hash = hashlib.new(algo)

    derived_key = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 100000)
    return derived_key
