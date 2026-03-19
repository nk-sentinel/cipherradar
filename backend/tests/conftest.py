import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app


@pytest.fixture
def app():
    """Create a fresh FastAPI app instance for testing.

    The app is created without lifespan so tests that don't need a database
    (e.g. health check) can run without any infrastructure.
    """
    return create_app(include_lifespan=False)


@pytest.fixture
async def client(app):
    """Async HTTP client for testing FastAPI endpoints.

    Uses httpx ASGITransport so no real server is started and
    no database connection is required for endpoints that don't use the DB.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
