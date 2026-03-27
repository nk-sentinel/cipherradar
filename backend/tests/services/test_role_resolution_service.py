"""Tests for role resolution service (D12)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.role_resolution_service import (
    ROLE_RANK,
    get_effective_role,
    resolve_role_for_group,
)


# ---------------------------------------------------------------------------
# Unit tests for get_effective_role
# ---------------------------------------------------------------------------


class TestGetEffectiveRole:
    def test_global_only_no_group(self) -> None:
        """When no group role is set, return the global role."""
        assert get_effective_role("developer", None) == "developer"
        assert get_effective_role("org_admin", None) == "org_admin"

    def test_group_wins_when_higher(self) -> None:
        """When group role is higher than global, group role wins."""
        assert get_effective_role("developer", "security_engineer") == "security_engineer"
        assert get_effective_role("guest", "team_manager") == "team_manager"

    def test_global_wins_when_higher(self) -> None:
        """When global role is higher than group, global role wins."""
        assert get_effective_role("org_admin", "developer") == "org_admin"
        assert get_effective_role("security_manager", "guest") == "security_manager"

    def test_same_rank(self) -> None:
        """When roles are equal, global role is returned."""
        assert get_effective_role("developer", "developer") == "developer"

    def test_role_rank_completeness(self) -> None:
        """All 7 roles should be in the rank map."""
        expected_roles = {
            "guest", "developer", "compliance_auditor", "team_manager",
            "security_engineer", "security_manager", "org_admin",
        }
        assert set(ROLE_RANK.keys()) == expected_roles

    def test_rank_ordering(self) -> None:
        """Ranks should be monotonically increasing from guest to org_admin."""
        ordered = ["guest", "developer", "compliance_auditor", "team_manager",
                    "security_engineer", "security_manager", "org_admin"]
        for i in range(len(ordered) - 1):
            assert ROLE_RANK[ordered[i]] < ROLE_RANK[ordered[i + 1]]


# ---------------------------------------------------------------------------
# Async tests for resolve_role_for_group
# ---------------------------------------------------------------------------


class TestResolveRoleForGroup:
    @pytest.mark.asyncio
    async def test_no_group_membership(self) -> None:
        """When user has no group membership, returns global role."""
        session = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result_mock)

        role = await resolve_role_for_group(
            user_id=str(uuid.uuid4()),
            user_role="developer",
            group_id=str(uuid.uuid4()),
            session=session,
        )
        assert role == "developer"

    @pytest.mark.asyncio
    async def test_group_role_higher(self) -> None:
        """When group role is higher, it takes precedence."""
        session = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = "security_manager"
        session.execute = AsyncMock(return_value=result_mock)

        role = await resolve_role_for_group(
            user_id=str(uuid.uuid4()),
            user_role="developer",
            group_id=str(uuid.uuid4()),
            session=session,
        )
        assert role == "security_manager"
