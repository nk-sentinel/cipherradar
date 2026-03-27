"""Tests for artifact registry service (D2)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.models.artifact_registry import ArtifactRegistry
from app.services.artifact_registry_service import ArtifactRegistryService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_registry(
    *,
    org_id: uuid.UUID | None = None,
    name: str = "JFrog",
    registry_type: str = "jfrog",
    url: str = "https://jfrog.example.com",
    enabled: bool = True,
) -> MagicMock:
    r = MagicMock(spec=ArtifactRegistry)
    r.id = uuid.uuid4()
    r.org_id = org_id or uuid.uuid4()
    r.name = name
    r.registry_type = registry_type
    r.url = url
    r.auth_token_encrypted = None
    r.enabled = enabled
    r.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    r.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return r


def _make_actor(*, org_id: uuid.UUID | None = None) -> MagicMock:
    actor = MagicMock()
    actor.user_id = str(uuid.uuid4())
    actor.org_id = str(org_id or uuid.uuid4())
    actor.role = "org_admin"
    return actor


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

service = ArtifactRegistryService()


@pytest.mark.asyncio
async def test_list_registries() -> None:
    """list_registries returns all registries for the org."""
    org_id = uuid.uuid4()
    reg1 = _make_registry(org_id=org_id, name="Docker Hub")
    reg2 = _make_registry(org_id=org_id, name="ECR")

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalars.return_value.all.return_value = [reg1, reg2]
    session.execute = AsyncMock(return_value=result_mock)

    result = await service.list_registries(org_id, session)

    assert len(result) == 2
    assert result[0].name == "Docker Hub"
    assert result[1].name == "ECR"


@pytest.mark.asyncio
async def test_create_registry() -> None:
    """create_registry persists a new registry and returns response."""
    from app.schemas.artifact_registry import RegistryCreate

    org_id = uuid.uuid4()
    actor = _make_actor(org_id=org_id)
    data = RegistryCreate(
        name="My JFrog",
        registry_type="jfrog",
        url="https://jfrog.example.com",
    )

    session = AsyncMock()

    async def mock_refresh(obj: MagicMock) -> None:
        obj.id = uuid.uuid4()
        obj.org_id = org_id
        obj.name = data.name
        obj.registry_type = data.registry_type
        obj.url = data.url
        obj.enabled = True
        obj.auth_token_encrypted = None
        obj.created_at = datetime.now(timezone.utc)
        obj.updated_at = datetime.now(timezone.utc)

    session.refresh = mock_refresh

    result = await service.create_registry(org_id, data, actor, session)

    assert result.name == "My JFrog"
    assert result.registry_type == "jfrog"
    assert session.add.call_count >= 1


@pytest.mark.asyncio
async def test_update_registry() -> None:
    """update_registry modifies fields on an existing registry."""
    from app.schemas.artifact_registry import RegistryUpdate

    org_id = uuid.uuid4()
    registry = _make_registry(org_id=org_id, name="Old Name")
    actor = _make_actor(org_id=org_id)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = registry
    session.execute = AsyncMock(return_value=result_mock)

    data = RegistryUpdate(name="New Name")
    result = await service.update_registry(registry.id, org_id, data, actor, session)

    assert registry.name == "New Name"


@pytest.mark.asyncio
async def test_delete_registry() -> None:
    """delete_registry removes the registry."""
    org_id = uuid.uuid4()
    registry = _make_registry(org_id=org_id)
    actor = _make_actor(org_id=org_id)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = registry
    session.execute = AsyncMock(return_value=result_mock)

    await service.delete_registry(registry.id, org_id, actor, session)

    session.delete.assert_awaited_once_with(registry)


@pytest.mark.asyncio
async def test_test_connection() -> None:
    """test_connection returns success for a valid registry (mock)."""
    org_id = uuid.uuid4()
    registry = _make_registry(org_id=org_id)

    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = registry
    session.execute = AsyncMock(return_value=result_mock)

    result = await service.test_connection(registry.id, org_id, session)

    assert result.success is True
    assert result.latency_ms is not None


@pytest.mark.asyncio
async def test_create_invalid_type() -> None:
    """create_registry rejects invalid registry types."""
    from app.schemas.artifact_registry import RegistryCreate

    org_id = uuid.uuid4()
    actor = _make_actor(org_id=org_id)
    data = RegistryCreate(
        name="Bad",
        registry_type="invalid_type",
        url="https://example.com",
    )

    session = AsyncMock()

    with pytest.raises(HTTPException) as exc_info:
        await service.create_registry(org_id, data, actor, session)

    assert exc_info.value.status_code == 400
    assert "invalid registry type" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_get_registry_not_found() -> None:
    """get_registry raises 404 for unknown registry."""
    session = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=result_mock)

    with pytest.raises(HTTPException) as exc_info:
        await service.get_registry(uuid.uuid4(), uuid.uuid4(), session)

    assert exc_info.value.status_code == 404
