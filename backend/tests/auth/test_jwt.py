"""Unit tests for JWT token management, API key helpers, and RBAC guards."""

from __future__ import annotations

from datetime import timedelta

import pytest
from jose import JWTError

from app.auth.api_keys import generate_api_key, hash_api_key, verify_api_key
from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.auth.roles import (
    API_KEY_CREATOR_ROLES,
    ROLE_DEFAULT_SCOPES,
    Role,
    Scope,
)

# -----------------------------------------------------------------------
# JWT access token
# -----------------------------------------------------------------------


class TestAccessToken:
    def test_create_and_decode(self) -> None:
        token = create_access_token(user_id="user-1", role="org_admin", scopes=["scan:read"])
        payload = decode_token(token)

        assert payload["sub"] == "user-1"
        assert payload["role"] == "org_admin"
        assert payload["scopes"] == ["scan:read"]
        assert payload["type"] == "access"

    def test_expired_token_raises(self) -> None:
        token = create_access_token(
            user_id="user-1",
            role="developer",
            scopes=[],
            expires_delta=timedelta(seconds=-1),
        )
        with pytest.raises(JWTError):
            decode_token(token)

    def test_tampered_token_raises(self) -> None:
        token = create_access_token(user_id="user-1", role="developer", scopes=[])
        with pytest.raises(JWTError):
            decode_token(token + "tampered")


# -----------------------------------------------------------------------
# JWT refresh token
# -----------------------------------------------------------------------


class TestRefreshToken:
    def test_create_and_decode(self) -> None:
        token = create_refresh_token(user_id="user-2")
        payload = decode_token(token)

        assert payload["sub"] == "user-2"
        assert payload["type"] == "refresh"
        # Refresh tokens should NOT contain role or scopes
        assert "role" not in payload
        assert "scopes" not in payload

    def test_expired_refresh_raises(self) -> None:
        token = create_refresh_token(user_id="user-2", expires_delta=timedelta(seconds=-1))
        with pytest.raises(JWTError):
            decode_token(token)


# -----------------------------------------------------------------------
# API key helpers
# -----------------------------------------------------------------------


class TestApiKeys:
    def test_generate_returns_prefixed_key_and_hash(self) -> None:
        key, key_hash = generate_api_key()
        assert key.startswith("cbom_sk_")
        assert len(key_hash) == 64  # SHA-256 hex digest

    def test_hash_is_deterministic(self) -> None:
        key = "cbom_sk_test123"
        assert hash_api_key(key) == hash_api_key(key)

    def test_verify_correct_key(self) -> None:
        key, key_hash = generate_api_key()
        assert verify_api_key(key, key_hash) is True

    def test_verify_wrong_key(self) -> None:
        _, key_hash = generate_api_key()
        assert verify_api_key("cbom_sk_wrong", key_hash) is False


# -----------------------------------------------------------------------
# RBAC constants
# -----------------------------------------------------------------------


class TestRoles:
    def test_all_roles_have_default_scopes(self) -> None:
        for role in Role:
            assert role in ROLE_DEFAULT_SCOPES, f"Role {role} missing from ROLE_DEFAULT_SCOPES"

    def test_org_admin_has_all_scopes(self) -> None:
        admin_scopes = set(ROLE_DEFAULT_SCOPES[Role.ORG_ADMIN])
        assert admin_scopes == set(Scope)

    def test_guest_has_minimal_scopes(self) -> None:
        guest_scopes = set(ROLE_DEFAULT_SCOPES[Role.GUEST])
        assert Scope.SCAN_WRITE not in guest_scopes
        assert Scope.PROJECT_WRITE not in guest_scopes

    def test_api_key_creator_roles(self) -> None:
        assert Role.ORG_ADMIN in API_KEY_CREATOR_ROLES
        assert Role.SECURITY_MANAGER in API_KEY_CREATOR_ROLES
        assert Role.SECURITY_ENGINEER in API_KEY_CREATOR_ROLES
        assert Role.DEVELOPER not in API_KEY_CREATOR_ROLES

    def test_role_checking(self) -> None:
        """Roles are comparable as strings."""
        assert Role.ORG_ADMIN == "org_admin"
        assert Role.DEVELOPER == "developer"
        assert Role.GUEST != "developer"


class TestScopeChecking:
    def test_scope_subset_check(self) -> None:
        user_scopes = {Scope.SCAN_READ, Scope.CBOM_READ}
        required = {Scope.SCAN_READ}
        assert required.issubset(user_scopes)

    def test_scope_missing_check(self) -> None:
        user_scopes = {Scope.SCAN_READ}
        required = {Scope.SCAN_WRITE}
        assert not required.issubset(user_scopes)
