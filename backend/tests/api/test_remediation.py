"""Tests for the remediation API endpoints — consent, caching, generation."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_session
from app.main import create_app
from app.services.llm.base import RemediationResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_FINDING_ID = uuid.uuid4()
FAKE_SCAN_ID = uuid.uuid4()
FAKE_PROJECT_ID = uuid.uuid4()
FAKE_ORG_ID = uuid.uuid4()


def _make_fake_finding(
    finding_id: uuid.UUID | None = None,
) -> MagicMock:
    """Build a mock Finding ORM object with code context."""
    f = MagicMock(
        spec=[
            "id", "scan_id", "project_id", "org_id",
            "rule_id", "name", "severity", "confidence",
            "quantum_status", "asset_type", "location_file",
            "location_line", "properties", "created_at", "updated_at",
        ]
    )
    f.id = finding_id or FAKE_FINDING_ID
    f.scan_id = FAKE_SCAN_ID
    f.project_id = FAKE_PROJECT_ID
    f.org_id = FAKE_ORG_ID
    f.rule_id = "cbom-python-md5-usage"
    f.name = "MD5 hash function"
    f.severity = "high"
    f.confidence = "high"
    f.quantum_status = "broken"
    f.asset_type = "Hash"
    f.location_file = "auth/hash.py"
    f.location_line = 12
    f.properties = {
        "algorithm": "MD5",
        "detection_pass": 1,
        "language": "python",
        "library": "hashlib",
        "code": {
            "start_line": 10,
            "lines": [
                "import hashlib",
                "",
                "digest = hashlib.md5(data).hexdigest()",
            ],
            "highlight_lines": [12],
        },
    }
    return f


SAMPLE_REMEDIATION = RemediationResult(
    original_code="import hashlib\n\ndigest = hashlib.md5(data).hexdigest()",
    fixed_code="import hashlib\n\ndigest = hashlib.sha256(data).hexdigest()",
    explanation="MD5 is cryptographically broken. SHA-256 is a secure replacement.",
    language="python",
    confidence=0.85,
    provider="anthropic",
)


@pytest.fixture
def app():
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# ---------------------------------------------------------------------------
# POST /api/v1/remediation/findings/{finding_id}/remediate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remediate_requires_consent(app, client: AsyncClient) -> None:
    """Should return 400 when consent is false."""
    response = await client.post(
        f"/api/v1/remediation/findings/{FAKE_FINDING_ID}/remediate",
        json={"consent": False},
    )
    assert response.status_code == 400
    assert "consent" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_remediate_finding_not_found(app, client: AsyncClient) -> None:
    """Should return 404 when finding does not exist."""
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=result_mock)

    response = await client.post(
        f"/api/v1/remediation/findings/{uuid.uuid4()}/remediate",
        json={"consent": True},
    )
    assert response.status_code == 404
    assert "finding" in response.json()["detail"].lower()

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_remediate_success(app, client: AsyncClient) -> None:
    """Should generate a remediation when consent is given and finding exists."""
    fake_finding = _make_fake_finding()
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = fake_finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    with (
        patch(
            "app.api.v1.remediation.get_cached_remediation",
            new_callable=AsyncMock,
            return_value=None,
        ),
        patch(
            "app.api.v1.remediation.create_llm_provider",
        ) as mock_factory,
        patch(
            "app.api.v1.remediation.set_cached_remediation",
            new_callable=AsyncMock,
        ),
    ):
        mock_provider = AsyncMock()
        mock_provider.generate_remediation = AsyncMock(return_value=SAMPLE_REMEDIATION)
        mock_factory.return_value = mock_provider

        response = await client.post(
            f"/api/v1/remediation/findings/{FAKE_FINDING_ID}/remediate",
            json={"consent": True},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["findingId"] == str(FAKE_FINDING_ID)
    assert "sha256" in body["fixedCode"].lower()
    assert body["provider"] == "anthropic"
    assert body["confidence"] == 0.85
    assert body["cached"] is False

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_remediate_returns_cached(app, client: AsyncClient) -> None:
    """Should return cached result without calling LLM when cache hit."""
    fake_finding = _make_fake_finding()
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = fake_finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    with patch(
        "app.api.v1.remediation.get_cached_remediation",
        new_callable=AsyncMock,
        return_value=SAMPLE_REMEDIATION,
    ):
        response = await client.post(
            f"/api/v1/remediation/findings/{FAKE_FINDING_ID}/remediate",
            json={"consent": True},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is True
    assert body["provider"] == "anthropic"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/remediation/findings/{finding_id}/remediation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_remediation_cached(app, client: AsyncClient) -> None:
    """Should return cached remediation on GET."""
    fake_finding = _make_fake_finding()
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = fake_finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    with patch(
        "app.api.v1.remediation.get_cached_remediation",
        new_callable=AsyncMock,
        return_value=SAMPLE_REMEDIATION,
    ):
        response = await client.get(
            f"/api/v1/remediation/findings/{FAKE_FINDING_ID}/remediation",
        )

    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is True

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_get_remediation_not_cached(app, client: AsyncClient) -> None:
    """Should return 404 when no cached remediation exists."""
    fake_finding = _make_fake_finding()
    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = fake_finding
    mock_session.execute = AsyncMock(return_value=result_mock)

    with patch(
        "app.api.v1.remediation.get_cached_remediation",
        new_callable=AsyncMock,
        return_value=None,
    ):
        response = await client.get(
            f"/api/v1/remediation/findings/{FAKE_FINDING_ID}/remediation",
        )

    assert response.status_code == 404
    assert "cached" in response.json()["detail"].lower()

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /api/v1/remediation/batch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_remediate_requires_consent(app, client: AsyncClient) -> None:
    """Should return 400 when consent is false for batch."""
    response = await client.post(
        "/api/v1/remediation/batch",
        json={
            "findingIds": [str(uuid.uuid4())],
            "consent": False,
        },
    )
    assert response.status_code == 400
    assert "consent" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_batch_remediate_success(app, client: AsyncClient) -> None:
    """Should remediate multiple findings in one request."""
    fid1 = uuid.uuid4()
    fid2 = uuid.uuid4()
    finding1 = _make_fake_finding(finding_id=fid1)
    finding2 = _make_fake_finding(finding_id=fid2)

    mock_session = AsyncMock()

    async def _override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = _override_get_session

    # Two execute calls for two findings
    result1 = MagicMock()
    result1.scalar_one_or_none.return_value = finding1
    result2 = MagicMock()
    result2.scalar_one_or_none.return_value = finding2
    mock_session.execute = AsyncMock(side_effect=[result1, result2])

    with (
        patch(
            "app.api.v1.remediation.get_cached_remediation",
            new_callable=AsyncMock,
            return_value=None,
        ),
        patch(
            "app.api.v1.remediation.create_llm_provider",
        ) as mock_factory,
        patch(
            "app.api.v1.remediation.set_cached_remediation",
            new_callable=AsyncMock,
        ),
    ):
        mock_provider = AsyncMock()
        mock_provider.generate_remediation = AsyncMock(return_value=SAMPLE_REMEDIATION)
        mock_factory.return_value = mock_provider

        response = await client.post(
            "/api/v1/remediation/batch",
            json={
                "findingIds": [str(fid1), str(fid2)],
                "consent": True,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2

    app.dependency_overrides.clear()
