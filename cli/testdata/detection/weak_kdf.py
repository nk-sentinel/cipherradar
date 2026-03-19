import hashlib

# BAD: low iteration count (1000 < 100000)
derived_key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)

# GOOD: sufficient iteration count
good_key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 600000)
