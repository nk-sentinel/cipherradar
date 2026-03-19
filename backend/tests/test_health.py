import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check_returns_ok(client: AsyncClient) -> None:
    """GET /api/v1/health should return 200 with status=ok and version."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"


@pytest.mark.asyncio
async def test_health_check_response_schema(client: AsyncClient) -> None:
    """Health response should contain the expected keys."""
    response = await client.get("/api/v1/health")
    body = response.json()
    assert "status" in body
    assert "version" in body
    assert "checks" in body
