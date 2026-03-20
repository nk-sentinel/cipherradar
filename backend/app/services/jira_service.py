"""Jira integration service — OAuth 2.0 connection and ticket creation.

Provides auto-ticket creation on policy violations (T-02) and critical
findings (T-03) with deduplication against existing open tickets.
"""

import logging

import httpx

logger = logging.getLogger(__name__)

# Atlassian OAuth 2.0 endpoints
ATLASSIAN_AUTH_URL = "https://auth.atlassian.com/authorize"
ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ATLASSIAN_API_BASE = "https://api.atlassian.com"


class JiraService:
    """Manages Jira OAuth connections and automatic ticket creation."""

    def __init__(self) -> None:
        # Pluggable persistence callbacks — set by the app layer or tests.
        self._store_connection = None  # async (record: dict) -> None
        self._get_connection = None  # async (org_id: str) -> dict | None
        self._find_existing_ticket = None  # async (org_id, finding_id) -> dict | None
        self._store_ticket = None  # async (record: dict) -> None

        # OAuth app credentials (set from settings)
        self.client_id: str = ""
        self.client_secret: str = ""
        self.redirect_uri: str = ""

    # -- DI setters ---------------------------------------------------------

    def set_store_connection(self, fn) -> None:  # noqa: ANN001
        self._store_connection = fn

    def set_get_connection(self, fn) -> None:  # noqa: ANN001
        self._get_connection = fn

    def set_find_existing_ticket(self, fn) -> None:  # noqa: ANN001
        self._find_existing_ticket = fn

    def set_store_ticket(self, fn) -> None:  # noqa: ANN001
        self._store_ticket = fn

    def configure(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        """Set OAuth app credentials."""
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    # -- OAuth flow ---------------------------------------------------------

    def get_authorize_url(self, state: str) -> str:
        """Return the Atlassian OAuth 2.0 authorisation URL."""
        params = (
            f"audience=api.atlassian.com"
            f"&client_id={self.client_id}"
            f"&scope=read%3Ajira-work%20write%3Ajira-work%20offline_access"
            f"&redirect_uri={self.redirect_uri}"
            f"&state={state}"
            f"&response_type=code"
            f"&prompt=consent"
        )
        return f"{ATLASSIAN_AUTH_URL}?{params}"

    async def exchange_code(self, code: str) -> dict:
        """Exchange an OAuth authorisation code for access + refresh tokens.

        Returns:
            Dict with ``access_token``, ``refresh_token``, ``cloud_id``, ``site_name``.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                ATLASSIAN_TOKEN_URL,
                json={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                },
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()

            # Fetch accessible Jira cloud sites
            sites_resp = await client.get(
                f"{ATLASSIAN_API_BASE}/oauth/token/accessible-resources",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            sites_resp.raise_for_status()
            sites = sites_resp.json()

        cloud_id = sites[0]["id"] if sites else ""
        site_name = sites[0].get("name", "") if sites else ""

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "cloud_id": cloud_id,
            "site_name": site_name,
        }

    async def connect(self, org_id: str, code: str) -> dict:
        """Full OAuth connect flow: exchange code and persist connection.

        Returns:
            Connection record dict.
        """
        token_data = await self.exchange_code(code)
        record = {
            "org_id": org_id,
            "cloud_id": token_data["cloud_id"],
            "site_name": token_data["site_name"],
            "access_token": token_data["access_token"],
            "refresh_token": token_data["refresh_token"],
            "connected": True,
        }

        if self._store_connection is not None:
            await self._store_connection(record)

        return record

    async def get_status(self, org_id: str) -> dict:
        """Return the current Jira connection status for an organisation."""
        if self._get_connection is None:
            return {"connected": False}

        connection = await self._get_connection(org_id)
        if connection is None:
            return {"connected": False}

        return {
            "connected": connection.get("connected", False),
            "site_name": connection.get("site_name", ""),
            "cloud_id": connection.get("cloud_id", ""),
        }

    # -- Ticket creation with deduplication ---------------------------------

    async def create_ticket(self, org_id: str, finding: dict, project_key: str) -> dict | None:
        """Create a Jira ticket for a finding, with deduplication.

        Checks for an existing open ticket for the same finding before creating.

        Args:
            org_id: Organisation ID.
            finding: Finding dict with ``id``, ``name``, ``severity``,
                ``location_file``, ``location_line``, ``quantum_status``, etc.
            project_key: Jira project key (e.g. ``"SEC"``).

        Returns:
            Created/existing ticket dict, or None if no connection.
        """
        finding_id = str(finding.get("id", ""))

        # Deduplication check
        if self._find_existing_ticket is not None:
            existing = await self._find_existing_ticket(org_id, finding_id)
            if existing is not None:
                logger.info("Existing Jira ticket found for finding %s: %s", finding_id, existing.get("key"))
                return existing

        # Get connection
        if self._get_connection is None:
            return None
        connection = await self._get_connection(org_id)
        if connection is None or not connection.get("connected"):
            return None

        # Build ticket
        summary = f"[CipherRadar] {finding.get('severity', 'UNKNOWN').upper()}: {finding.get('name', 'Unknown finding')}"
        description = self._build_ticket_description(finding)
        severity_label = finding.get("severity", "unknown").lower()
        labels = ["cbom", "crypto", severity_label]

        issue_data = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary[:255],
                "description": description,
                "issuetype": {"name": "Bug"},
                "labels": labels,
            }
        }

        # Create via Jira REST API
        cloud_id = connection["cloud_id"]
        access_token = connection["access_token"]

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{ATLASSIAN_API_BASE}/ex/jira/{cloud_id}/rest/api/3/issue",
                    json=issue_data,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                result = resp.json()
        except Exception:
            logger.warning("Failed to create Jira ticket for finding %s", finding_id, exc_info=True)
            return None

        ticket_record = {
            "org_id": org_id,
            "finding_id": finding_id,
            "jira_key": result.get("key", ""),
            "jira_id": result.get("id", ""),
            "jira_url": f"https://{connection.get('site_name', '')}.atlassian.net/browse/{result.get('key', '')}",
        }

        if self._store_ticket is not None:
            await self._store_ticket(ticket_record)

        return ticket_record

    @staticmethod
    def _build_ticket_description(finding: dict) -> str:
        """Build the Jira ticket description in Atlassian wiki markup."""
        name = finding.get("name", "Unknown")
        location_file = finding.get("location_file", "unknown")
        location_line = finding.get("location_line", 0)
        quantum_status = finding.get("quantum_status", "unknown")
        severity = finding.get("severity", "unknown")
        properties = finding.get("properties", {}) or {}
        policy_violated = properties.get("policy_violated", "N/A")
        remediation = properties.get("remediation", "See CipherRadar dashboard for remediation guidance.")
        cwe = properties.get("cwe", "N/A")

        return (
            f"h2. Finding Summary\n"
            f"Algorithm: {name}\n"
            f"File: {location_file}, Line {location_line}\n"
            f"Quantum Status: {quantum_status}\n"
            f"Policy Violated: {policy_violated}\n\n"
            f"h2. Risk\n"
            f"Severity: {severity}\n"
            f"CWE: {cwe}\n\n"
            f"h2. Remediation\n"
            f"{remediation}\n"
        )


# Module-level singleton
jira_service = JiraService()
