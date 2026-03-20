"""Tests for the Jira integration service — ticket creation, deduplication."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.services.jira_service import JiraService

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def jira_svc() -> JiraService:
    """Fresh JiraService with mocked persistence."""
    svc = JiraService()
    svc.configure(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="https://cipherradar.io/callback",
    )
    svc.set_store_connection(AsyncMock())
    svc.set_get_connection(
        AsyncMock(
            return_value={
                "org_id": "org-1",
                "cloud_id": "cloud-123",
                "site_name": "mysite",
                "access_token": "test-token",
                "connected": True,
            }
        )
    )
    svc.set_find_existing_ticket(AsyncMock(return_value=None))
    svc.set_store_ticket(AsyncMock())
    return svc


FAKE_FINDING = {
    "id": str(uuid.uuid4()),
    "name": "RSA-1024",
    "severity": "critical",
    "location_file": "src/crypto/KeyManager.java",
    "location_line": 42,
    "quantum_status": "quantum-vulnerable",
    "properties": {
        "policy_violated": "MIN_KEY_SIZE",
        "remediation": "Upgrade to RSA-2048 or ML-KEM-768",
        "cwe": "CWE-326",
    },
}


# ---------------------------------------------------------------------------
# Ticket creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_ticket_calls_jira_api(jira_svc: JiraService) -> None:
    """create_ticket() should POST to the Jira REST API."""
    with patch("app.services.jira_service.httpx.AsyncClient") as mock_client_cls:
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "10001", "key": "SEC-42"}
        mock_response.raise_for_status = AsyncMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await jira_svc.create_ticket("org-1", FAKE_FINDING, "SEC")

        assert result is not None
        assert result["jira_key"] == "SEC-42"
        assert result["finding_id"] == FAKE_FINDING["id"]
        mock_client.post.assert_called_once()


@pytest.mark.asyncio
async def test_create_ticket_stores_ticket_record(jira_svc: JiraService) -> None:
    """create_ticket() should persist the ticket record via callback."""
    with patch("app.services.jira_service.httpx.AsyncClient") as mock_client_cls:
        mock_response = AsyncMock()
        mock_response.json.return_value = {"id": "10001", "key": "SEC-42"}
        mock_response.raise_for_status = AsyncMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        await jira_svc.create_ticket("org-1", FAKE_FINDING, "SEC")

        jira_svc._store_ticket.assert_called_once()
        stored = jira_svc._store_ticket.call_args[0][0]
        assert stored["jira_key"] == "SEC-42"
        assert stored["org_id"] == "org-1"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_ticket_deduplicates(jira_svc: JiraService) -> None:
    """create_ticket() should return existing ticket instead of creating a new one."""
    existing_ticket = {
        "jira_key": "SEC-99",
        "finding_id": FAKE_FINDING["id"],
        "key": "SEC-99",
    }
    jira_svc.set_find_existing_ticket(AsyncMock(return_value=existing_ticket))

    result = await jira_svc.create_ticket("org-1", FAKE_FINDING, "SEC")

    assert result is not None
    assert result["jira_key"] == "SEC-99"
    # Should NOT have called the store callback since we returned an existing ticket
    jira_svc._store_ticket.assert_not_called()


# ---------------------------------------------------------------------------
# No connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_ticket_returns_none_when_no_connection(jira_svc: JiraService) -> None:
    """create_ticket() should return None if no Jira connection exists."""
    jira_svc.set_get_connection(AsyncMock(return_value=None))

    result = await jira_svc.create_ticket("org-1", FAKE_FINDING, "SEC")

    assert result is None


@pytest.mark.asyncio
async def test_create_ticket_returns_none_when_disconnected(jira_svc: JiraService) -> None:
    """create_ticket() should return None if Jira connection is not active."""
    jira_svc.set_get_connection(AsyncMock(return_value={"connected": False}))

    result = await jira_svc.create_ticket("org-1", FAKE_FINDING, "SEC")

    assert result is None


# ---------------------------------------------------------------------------
# Connection status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_status_connected(jira_svc: JiraService) -> None:
    """get_status() should return connected=True with site info."""
    result = await jira_svc.get_status("org-1")

    assert result["connected"] is True
    assert result["site_name"] == "mysite"
    assert result["cloud_id"] == "cloud-123"


@pytest.mark.asyncio
async def test_get_status_no_callback() -> None:
    """get_status() should return connected=False when no callback is set."""
    svc = JiraService()
    result = await svc.get_status("org-1")

    assert result["connected"] is False


# ---------------------------------------------------------------------------
# Ticket description
# ---------------------------------------------------------------------------


def test_build_ticket_description_contains_finding_details() -> None:
    """_build_ticket_description() should include finding metadata."""
    desc = JiraService._build_ticket_description(FAKE_FINDING)

    assert "RSA-1024" in desc
    assert "src/crypto/KeyManager.java" in desc
    assert "42" in desc
    assert "quantum-vulnerable" in desc
    assert "MIN_KEY_SIZE" in desc
    assert "CWE-326" in desc


# ---------------------------------------------------------------------------
# Authorize URL
# ---------------------------------------------------------------------------


def test_get_authorize_url_contains_params(jira_svc: JiraService) -> None:
    """get_authorize_url() should return a valid Atlassian OAuth URL."""
    url = jira_svc.get_authorize_url("test-state")

    assert "auth.atlassian.com/authorize" in url
    assert "client_id=test-client-id" in url
    assert "state=test-state" in url
    assert "response_type=code" in url
