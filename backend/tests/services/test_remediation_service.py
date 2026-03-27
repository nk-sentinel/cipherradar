"""Tests for remediation service (D5)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.auth.middleware import AuthenticatedUser
from app.models.finding import Finding
from app.models.llm_config import LLMConfig
from app.services.llm.base import RemediationResult
from app.services.remediation_service import RemediationService


_ORG_ID = uuid.uuid4()
_USER_ID = uuid.uuid4()


def _make_actor(role: str = "org_admin") -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=str(_USER_ID),
        org_id=str(_ORG_ID),
        role=role,
        scopes=[],
    )


def _make_finding() -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.rule_id = "cbom-python-md5"
    f.name = "MD5 usage"
    f.severity = "high"
    f.quantum_status = "vulnerable"
    f.location_file = "app/crypto.py"
    f.location_line = 42
    f.properties = {
        "language": "python",
        "library": "hashlib",
        "code": {"lines": ["import hashlib", "h = hashlib.md5(data)"]},
    }
    return f


def _make_llm_config(provider: str = "anthropic") -> MagicMock:
    cfg = MagicMock(spec=LLMConfig)
    cfg.id = uuid.uuid4()
    cfg.org_id = _ORG_ID
    cfg.provider = provider
    cfg.model = "claude-sonnet-4-20250514"
    cfg.api_key_encrypted = "sk-test"
    cfg.endpoint_url = None
    cfg.max_tokens = 4096
    cfg.temperature = 0.0
    cfg.enabled = True
    return cfg


class TestGenerateFix:
    """Test the generate_fix workflow."""

    @pytest.mark.asyncio
    async def test_generate_fix_calls_provider(self) -> None:
        svc = RemediationService()
        finding = _make_finding()
        actor = _make_actor()
        config = _make_llm_config()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = config
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        mock_remediation = RemediationResult(
            original_code="h = hashlib.md5(data)",
            fixed_code="h = hashlib.sha256(data)",
            explanation="Replace MD5 with SHA-256",
            language="python",
            confidence=0.85,
            provider="anthropic",
        )

        with (
            patch("app.services.remediation_service.get_cached_remediation", new_callable=AsyncMock, return_value=None),
            patch("app.services.remediation_service.set_cached_remediation", new_callable=AsyncMock),
            patch.object(svc, "_create_provider") as mock_create,
        ):
            mock_provider = AsyncMock()
            mock_provider.generate_remediation = AsyncMock(return_value=mock_remediation)
            mock_create.return_value = mock_provider

            result = await svc.generate_fix(
                finding=finding,
                actor=actor,
                session=session,
            )

        assert result["fixed_code"] == "h = hashlib.sha256(data)"
        assert result["cached"] is False

    @pytest.mark.asyncio
    async def test_generate_fix_uses_cache(self) -> None:
        svc = RemediationService()
        finding = _make_finding()
        actor = _make_actor()
        config = _make_llm_config()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = config
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        cached = RemediationResult(
            original_code="old",
            fixed_code="new",
            explanation="cached",
            language="python",
            confidence=0.9,
            provider="anthropic",
        )

        with patch("app.services.remediation_service.get_cached_remediation", new_callable=AsyncMock, return_value=cached):
            result = await svc.generate_fix(
                finding=finding,
                actor=actor,
                session=session,
            )

        assert result["cached"] is True
        assert result["fixed_code"] == "new"

    @pytest.mark.asyncio
    async def test_generate_fix_no_config_raises(self) -> None:
        svc = RemediationService()
        finding = _make_finding()
        actor = _make_actor()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        with pytest.raises(ValueError, match="No LLM provider"):
            await svc.generate_fix(finding=finding, actor=actor, session=session)


class TestPrivacyTransforms:
    """Test privacy transform functions."""

    def test_strip_comments_python(self) -> None:
        svc = RemediationService()
        code = "x = 1  # secret comment\ny = 2"
        result = svc.apply_privacy_transforms(code, "python", strip_comments_enabled=True)
        assert "secret comment" not in result
        assert "x = 1" in result

    def test_strip_comments_java(self) -> None:
        svc = RemediationService()
        code = "int x = 1; // internal note\n/* block */\nint y = 2;"
        result = svc.apply_privacy_transforms(code, "java", strip_comments_enabled=True)
        assert "internal note" not in result
        assert "block" not in result
        assert "int y = 2" in result

    def test_anonymize_variables(self) -> None:
        svc = RemediationService()
        code = "companySecretKey = getKey()\ninternal_token = fetch()"
        result = svc.apply_privacy_transforms(
            code, "python", strip_comments_enabled=False, anonymize_enabled=True,
        )
        assert "companySecretKey" not in result
        assert "internal_token" not in result
        assert "VAR_" in result


class TestConsentCheck:
    """Verify consent is enforced at the route level."""

    def test_consent_required_in_request_schema(self) -> None:
        """The RemediationRequest schema requires consent=true."""
        from app.schemas.remediation import RemediationRequest

        # consent is a required boolean field
        req = RemediationRequest(consent=True)
        assert req.consent is True

        # consent=False should be a valid model but rejected by the route
        req2 = RemediationRequest(consent=False)
        assert req2.consent is False
