"""Admin security tests for Phase 4.5 Plan 5.

Verifies:
- LLM API key not exposed in GET response (masked/omitted)
- Custom rule YAML injection prevention
- Integration token not returned in plaintext from GET
- Audit log RBAC: SM+CA can read, SE scoped, DEV/TM/Guest denied
- Policy lock: SM cannot override locked rules

All tests run without a real database by overriding FastAPI dependencies.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.jwt import create_access_token
from app.auth.roles import ROLE_DEFAULT_SCOPES, Role, Scope
from app.main import create_app

if TYPE_CHECKING:
    from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

ORG_ID = str(uuid.uuid4())
USER_ID = str(uuid.uuid4())
GROUP_ID = str(uuid.uuid4())
RULE_ID = str(uuid.uuid4())


def _token_for_role(role: Role, org_id: str = ORG_ID) -> str:
    """Create a valid JWT for the given role."""
    scopes = [str(s) for s in ROLE_DEFAULT_SCOPES.get(role, [])]
    return create_access_token(
        user_id=USER_ID,
        role=str(role),
        scopes=scopes,
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app() -> FastAPI:
    """Create a test app without lifespan."""
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    """Async HTTP client wired to the test app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# LLM API key not exposed in GET response
# ---------------------------------------------------------------------------


class TestLLMApiKeyNotExposed:
    """Verify the GET /admin/llm-config response never leaks the raw API key."""

    @pytest.mark.asyncio
    async def test_llm_config_get_omits_api_key(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """GET /admin/llm-config should return api_key_set bool, not the raw key."""
        token = _token_for_role(Role.ORG_ADMIN)
        headers = {"Authorization": f"Bearer {token}"}

        mock_config = {
            "id": str(uuid.uuid4()),
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "endpoint_url": None,
            "max_tokens": 4096,
            "temperature": 0.0,
            "enabled": True,
            "api_key_set": True,
        }

        with patch(
            "app.services.llm_config_service.llm_config_service.get_config",
            new_callable=AsyncMock,
            return_value=mock_config,
        ):
            mock_session = AsyncMock()
            from app.db.session import get_session

            async def _override():
                yield mock_session

            app.dependency_overrides[get_session] = _override

            try:
                resp = await client.get("/api/v1/admin/llm-config", headers=headers)
                assert resp.status_code == 200

                data = resp.json()

                # Must NOT contain raw api_key field
                assert "apiKey" not in data, (
                    "Response must not contain raw 'apiKey' field"
                )
                assert "api_key" not in data, (
                    "Response must not contain raw 'api_key' field"
                )

                # Must contain the boolean indicator
                assert "apiKeySet" in data or "api_key_set" in data, (
                    "Response should contain 'apiKeySet' boolean"
                )

                # Verify no long secret-looking strings in the entire response
                resp_text = resp.text
                assert "sk-" not in resp_text, (
                    "Response contains what appears to be an API key prefix"
                )
            finally:
                app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Custom rule YAML injection prevention
# ---------------------------------------------------------------------------


class TestCustomRuleYAMLInjection:
    """Verify that malicious YAML payloads are rejected by the custom rule service."""

    @pytest.mark.asyncio
    async def test_yaml_injection_rejected(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """POST /admin/rules with YAML injection should be rejected."""
        token = _token_for_role(Role.ORG_ADMIN)
        headers = {"Authorization": f"Bearer {token}"}

        # Malicious YAML with Python code execution attempt
        malicious_pattern = "!!python/object/apply:os.system ['echo pwned']"

        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()

        from app.db.session import get_session

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override

        try:
            resp = await client.post(
                "/api/v1/admin/rules",
                json={
                    "name": "malicious-rule",
                    "description": "test",
                    "language": "python",
                    "patternType": "opengrep",
                    "pattern": malicious_pattern,
                    "severity": "high",
                },
                headers=headers,
            )
            # Should be rejected as invalid YAML rule (missing 'rules' key)
            assert resp.status_code == 400, (
                f"Expected 400 for malicious YAML, got {resp.status_code}: {resp.text}"
            )
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_yaml_missing_rules_key_rejected(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """POST /admin/rules with YAML missing 'rules' key should be rejected."""
        token = _token_for_role(Role.ORG_ADMIN)
        headers = {"Authorization": f"Bearer {token}"}

        # Valid YAML but missing the required 'rules' key
        bad_pattern = "id: test\npattern: foo\nmessage: bar"

        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()

        from app.db.session import get_session

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override

        try:
            resp = await client.post(
                "/api/v1/admin/rules",
                json={
                    "name": "bad-structure-rule",
                    "description": "test",
                    "language": "java",
                    "patternType": "opengrep",
                    "pattern": bad_pattern,
                    "severity": "medium",
                },
                headers=headers,
            )
            assert resp.status_code == 400, (
                f"Expected 400 for missing rules key, got {resp.status_code}: {resp.text}"
            )
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Integration token not returned in plaintext from GET
# ---------------------------------------------------------------------------


class TestIntegrationTokenNotExposed:
    """Verify GET /admin/integrations does not expose raw tokens."""

    @pytest.mark.asyncio
    async def test_integration_list_omits_token(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """GET /admin/integrations should not return raw PAT tokens."""
        token = _token_for_role(Role.ORG_ADMIN)
        headers = {"Authorization": f"Bearer {token}"}

        mock_session = AsyncMock()

        from app.db.session import get_session

        async def _override():
            yield mock_session

        app.dependency_overrides[get_session] = _override

        try:
            resp = await client.get("/api/v1/admin/integrations", headers=headers)
            assert resp.status_code == 200

            data = resp.json()
            resp_text = resp.text

            # Verify no token, secret, or credential fields with values
            assert "token_encrypted" not in resp_text, (
                "Response must not contain 'token_encrypted' field"
            )
            assert "tokenEncrypted" not in resp_text, (
                "Response must not contain 'tokenEncrypted' field"
            )

            # Check items don't have token fields
            items = data.get("items", [])
            for item in items:
                assert "token" not in item or item.get("token") is None, (
                    f"Integration item should not expose raw token: {item}"
                )
                assert "secret" not in item, (
                    f"Integration item should not expose 'secret' field: {item}"
                )
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Audit log RBAC enforcement
# ---------------------------------------------------------------------------


class TestAuditLogRBAC:
    """Verify audit log access control.

    SM + OA can read audit logs.
    SE, CA, DEV, TM, Guest should be denied (403).
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "role",
        [Role.ORG_ADMIN, Role.SECURITY_MANAGER],
    )
    async def test_audit_log_allowed_roles(
        self, app: FastAPI, client: AsyncClient, role: Role
    ) -> None:
        """OA and SM should be able to read audit logs."""
        token = _token_for_role(role)
        headers = {"Authorization": f"Bearer {token}"}

        mock_result = {
            "items": [],
            "total": 0,
            "page": 1,
            "per_page": 25,
        }

        with patch(
            "app.services.audit_log_query_service.audit_log_query_service.query",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            mock_session = AsyncMock()

            from app.db.session import get_session

            async def _override():
                yield mock_session

            app.dependency_overrides[get_session] = _override

            try:
                resp = await client.get("/api/v1/admin/audit-log", headers=headers)
                assert resp.status_code == 200, (
                    f"GET /admin/audit-log as {role}: expected 200, got {resp.status_code}"
                )
            finally:
                app.dependency_overrides.clear()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "role",
        [
            Role.SECURITY_ENGINEER,
            Role.COMPLIANCE_AUDITOR,
            Role.DEVELOPER,
            Role.TEAM_MANAGER,
            Role.GUEST,
        ],
    )
    async def test_audit_log_denied_roles(
        self, client: AsyncClient, role: Role
    ) -> None:
        """SE, CA, DEV, TM, Guest should be denied access to audit logs."""
        token = _token_for_role(role)
        headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get("/api/v1/admin/audit-log", headers=headers)
        assert resp.status_code == 403, (
            f"GET /admin/audit-log as {role}: expected 403, got {resp.status_code}"
        )

    @pytest.mark.asyncio
    async def test_audit_log_unauthenticated(self, client: AsyncClient) -> None:
        """Unauthenticated access to audit log should return 401."""
        resp = await client.get("/api/v1/admin/audit-log")
        assert resp.status_code == 401, (
            f"GET /admin/audit-log unauthenticated: expected 401, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Policy lock: SM cannot override locked rules
# ---------------------------------------------------------------------------


class TestPolicyLockEnforcement:
    """Verify that SM cannot override rules locked at org level."""

    @pytest.mark.asyncio
    async def test_sm_cannot_override_locked_rule(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """SM attempting to override a locked rule at group level should fail."""
        token = _token_for_role(Role.SECURITY_MANAGER)
        headers = {"Authorization": f"Bearer {token}"}

        # Mock: the org-level has a lock on "no-broken-algorithms"
        mock_locked_override = MagicMock()
        mock_locked_override.rule_id = "no-broken-algorithms"
        mock_locked_override.action = "lock"
        mock_locked_override.id = uuid.uuid4()
        mock_locked_override.reason = "Org policy"

        with (
            patch(
                "app.services.policy_service.policy_service.save_policy",
                new_callable=AsyncMock,
                side_effect=ValueError(
                    "Rule 'no-broken-algorithms' is locked at a higher level and cannot be overridden"
                ),
            ),
        ):
            mock_session = AsyncMock()
            mock_session.commit = AsyncMock()

            from app.db.session import get_session

            async def _override():
                yield mock_session

            app.dependency_overrides[get_session] = _override

            try:
                resp = await client.put(
                    f"/api/v1/policy/groups/{GROUP_ID}/effective",
                    json={
                        "ruleId": "no-broken-algorithms",
                        "action": "ignore",
                        "reason": "We use MD5 for checksums only",
                    },
                    headers=headers,
                )
                # Should fail because the rule is locked at org level
                assert resp.status_code == 400, (
                    f"Expected 400 for locked rule override, got {resp.status_code}: {resp.text}"
                )
                assert "locked" in resp.text.lower(), (
                    f"Error should mention 'locked': {resp.text}"
                )
            finally:
                app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_sm_cannot_lock_rules(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        """SM should not be able to set action='lock' (only OA can)."""
        token = _token_for_role(Role.SECURITY_MANAGER)
        headers = {"Authorization": f"Bearer {token}"}

        with patch(
            "app.services.policy_service.policy_service.save_policy",
            new_callable=AsyncMock,
            side_effect=PermissionError("Only Org Admin can lock policy rules"),
        ):
            mock_session = AsyncMock()
            mock_session.commit = AsyncMock()

            from app.db.session import get_session

            async def _override():
                yield mock_session

            app.dependency_overrides[get_session] = _override

            try:
                resp = await client.put(
                    "/api/v1/policy/effective",
                    json={
                        "ruleId": "no-ecb-mode",
                        "action": "lock",
                    },
                    headers=headers,
                )
                assert resp.status_code == 403, (
                    f"Expected 403 for SM locking rules, got {resp.status_code}: {resp.text}"
                )
            finally:
                app.dependency_overrides.clear()
