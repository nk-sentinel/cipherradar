require 'openssl'
require 'bcrypt'
require 'digest'

# ---------------------------------------------------------------------------
# OpenSSL::Cipher
# ---------------------------------------------------------------------------

# AES-256-CBC encryption
cipher = OpenSSL::Cipher.new("AES-256-CBC")
cipher.encrypt
cipher.key = OpenSSL::Random.random_bytes(32)
cipher.iv = OpenSSL::Random.random_bytes(16)
encrypted = cipher.update("sensitive data") + cipher.final

# DES-CBC (weak — should be HIGH severity)
des_cipher = OpenSSL::Cipher.new("DES-CBC")

# RC4 (broken — should be HIGH severity)
rc4_cipher = OpenSSL::Cipher.new("RC4")

# ---------------------------------------------------------------------------
# OpenSSL::Digest
# ---------------------------------------------------------------------------

# SHA-256
digest = OpenSSL::Digest::SHA256.new
digest.update("data")
sha256_hex = digest.hexdigest

# SHA-1 (broken — should be HIGH severity)
sha1_digest = OpenSSL::Digest::SHA1.digest("data")

# MD5 (broken — should be HIGH severity)
md5_digest = OpenSSL::Digest::MD5.hexdigest("data")

# ---------------------------------------------------------------------------
# OpenSSL::PKey
# ---------------------------------------------------------------------------

# RSA-2048 key generation
rsa_key = OpenSSL::PKey::RSA.new(2048)

# EC key generation
ec_key = OpenSSL::PKey::EC.generate("prime256v1")

# ---------------------------------------------------------------------------
# OpenSSL::SSL
# ---------------------------------------------------------------------------

ssl_context = OpenSSL::SSL::SSLContext.new

# ---------------------------------------------------------------------------
# BCrypt
# ---------------------------------------------------------------------------

password_hash = BCrypt::Password.create("my_password")
is_valid = BCrypt::Password.new(password_hash) == "my_password"

# ---------------------------------------------------------------------------
# Digest module
# ---------------------------------------------------------------------------

sha256_result = Digest::SHA256.hexdigest("data")
md5_result = Digest::MD5.hexdigest("data")
sha1_result = Digest::SHA1.hexdigest("data")
