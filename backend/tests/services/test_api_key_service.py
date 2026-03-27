"""Tests for API key management service (D7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.roles import Role
from app.models.api_key import APIKey
from app.services.api_key_service import ApiKeyService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _mock_session_for_create() -> AsyncMock:
    """Build an AsyncMock session for key creation."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


def _mock_session_with_keys(keys: list[MagicMock]) -> AsyncMock:
    """Build an AsyncMock session returning a list of keys from execute."""
    session = AsyncMock()
    result_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = keys
    result_mock.scalars.return_value = scalars_mock
    session.execute = AsyncMock(return_value=result_mock)
    return session


def _mock_session_with_single_key(key: MagicMock | None) -> AsyncMock:
    """Build an AsyncMock session returning a single key from execute."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = key
    session.execute = AsyncMock(return_value=result_mock)
    return session


def _make_api_key(
    *,
    user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    name: str = "test-key",
    scopes: list[str] | None = None,
) -> MagicMock:
    """Build a mock APIKey ORM object."""
    k = MagicMock(spec=APIKey)
    k.id = uuid.uuid4()
    k.user_id = user_id or _USER_ID
    k.org_id = org_id or _ORG_ID
    k.name = name
    k.key_hash = "fakehash"
    k.key_prefix = "cbom_sk_xxxx"
    k.scopes = scopes or ["scan:read"]
    k.created_at = datetime.now(UTC)
    k.expires_at = None
    k.last_used_at = None
    k.revoked_at = None
    return k


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestApiKeyCreate:
    @pytest.mark.asyncio
    async def test_create_returns_raw_key(self) -> None:
        service = ApiKeyService()
        session = _mock_session_for_create()

        with patch("app.services.api_key_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            api_key, plaintext = await service.create(
                name="ci-key",
                scopes=["scan:read", "scan:write"],
                expires_in_days=None,
                user_id=str(_USER_ID),
                user_role=str(Role.ORG_ADMIN),
                org_id=str(_ORG_ID),
                session=session,
            )

        # Plaintext key is returned and starts with cbom_sk_
        assert plaintext.startswith("cbom_sk_")
        assert api_key.name == "ci-key"
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_scopes_capped_by_role(self) -> None:
        service = ApiKeyService()
        session = _mock_session_for_create()

        with patch("app.services.api_key_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            # Guest can only have scan:read and cbom:read
            api_key, _ = await service.create(
                name="guest-key",
                scopes=["scan:read", "scan:write", "project:write"],
                expires_in_days=None,
                user_id=str(_USER_ID),
                user_role=str(Role.GUEST),
                org_id=str(_ORG_ID),
                session=session,
            )

        # scan:write and project:write should be capped
        assert "scan:write" not in api_key.scopes
        assert "project:write" not in api_key.scopes
        assert "scan:read" in api_key.scopes


class TestApiKeyList:
    @pytest.mark.asyncio
    async def test_list_shows_prefix_only(self) -> None:
        service = ApiKeyService()
        key = _make_api_key()
        session = _mock_session_with_keys([key])

        keys = await service.list_own(user_id=str(_USER_ID), session=session)
        assert len(keys) == 1
        assert keys[0].key_prefix == "cbom_sk_xxxx"
        # No raw key should be exposed
        assert not hasattr(keys[0], "plaintext_key")

    @pytest.mark.asyncio
    async def test_list_all_org(self) -> None:
        service = ApiKeyService()
        key1 = _make_api_key(name="key-1")
        key2 = _make_api_key(name="key-2", user_id=uuid.uuid4())
        session = _mock_session_with_keys([key1, key2])

        keys = await service.list_all_org(org_id=str(_ORG_ID), session=session)
        assert len(keys) == 2


class TestApiKeyRevoke:
    @pytest.mark.asyncio
    async def test_revoke_own(self) -> None:
        service = ApiKeyService()
        key = _make_api_key()
        session = _mock_session_with_single_key(key)

        with patch("app.services.api_key_service.audit_service") as mock_audit:
            mock_audit.log = AsyncMock()
            await service.revoke_own(
                key_id=str(key.id),
                user_id=str(_USER_ID),
                org_id=str(_ORG_ID),
                session=session,
            )

        assert key.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_not_found(self) -> None:
        service = ApiKeyService()
        session = _mock_session_with_single_key(None)

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.revoke_own(
                key_id=str(uuid.uuid4()),
                user_id=str(_USER_ID),
                org_id=str(_ORG_ID),
                session=session,
            )
        assert exc_info.value.status_code == 404


class TestGuestBlocked:
    @pytest.mark.asyncio
    async def test_guest_no_valid_scopes_blocked(self) -> None:
        """Guest requesting scopes they don't have should get no valid scopes error."""
        service = ApiKeyService()
        session = _mock_session_for_create()

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await service.create(
                name="bad-key",
                scopes=["project:write"],  # Guest can't have this
                expires_in_days=None,
                user_id=str(_USER_ID),
                user_role=str(Role.GUEST),
                org_id=str(_ORG_ID),
                session=session,
            )
        assert exc_info.value.status_code == 400
