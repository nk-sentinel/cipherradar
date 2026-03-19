"""API key generation and verification (ADR-013).

Keys are prefixed ``cbom_sk_`` for easy identification in logs and
secret-scanners.  Only the SHA-256 hash is stored in the database;
the plaintext key is returned once at creation time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_KEY_PREFIX = "cbom_sk_"
_KEY_BYTES = 32  # 256 bits of entropy


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key and its SHA-256 hash.

    Returns:
        A ``(plaintext_key, sha256_hash)`` tuple.  The plaintext key is
        shown to the user once; only the hash is persisted.
    """
    raw = secrets.token_urlsafe(_KEY_BYTES)
    key = f"{_KEY_PREFIX}{raw}"
    return key, hash_api_key(key)


def hash_api_key(key: str) -> str:
    """Return the hex-encoded SHA-256 hash of *key*.

    Args:
        key: The plaintext API key string (including prefix).
    """
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key: str, stored_hash: str) -> bool:
    """Verify an API key against a stored SHA-256 hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        key: The plaintext API key provided in the request.
        stored_hash: The hex-encoded SHA-256 hash from the database.

    Returns:
        ``True`` if the key matches the stored hash.
    """
    computed = hash_api_key(key)
    return hmac.compare_digest(computed, stored_hash)
