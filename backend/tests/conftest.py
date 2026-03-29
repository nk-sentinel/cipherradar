from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.main import create_app


def _make_admin_user() -> AuthenticatedUser:
    """Return a mock org-admin user for test auth."""
    return AuthenticatedUser(
        user_id="00000000-0000-4000-a000-000000000001",
        role="org_admin",
        scopes=["scan:read", "scan:write", "cbom:read", "project:read", "project:write", "report:read"],
        org_id="00000000-0000-4000-a000-000000000099",
        assignment_level="org",
        assigned_group_id=None,
        assigned_project_ids=[],
    )


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


@pytest.fixture
def mock_session():
    """AsyncMock session for tests that call endpoints needing DB."""
    session = AsyncMock()
    result = MagicMock()
    result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))
    result.scalar_one_or_none.return_value = None
    result.scalar.return_value = 0
    session.execute = AsyncMock(return_value=result)
    return session


@pytest.fixture
def app_with_session(app, mock_session):
    """App with get_session overridden to return mock (no auth)."""
    async def _override_session():
        yield mock_session
    app.dependency_overrides[get_session] = _override_session
    yield app
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def app_with_auth(app, mock_session):
    """App with get_session AND get_current_user overridden (authenticated as admin)."""
    async def _override_session():
        yield mock_session
    async def _override_user():
        return _make_admin_user()
    app.dependency_overrides[get_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user
    yield app
    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
async def client_with_auth(app_with_auth):
    """Client that uses mocked session + authenticated admin user."""
    transport = ASGITransport(app=app_with_auth)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
async def client_with_session(app_with_session):
    """Client that uses the mocked session."""
    transport = ASGITransport(app=app_with_session)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
