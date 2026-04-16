"""Jira config resolution and issue creation service (D18).

Handles hierarchical config (project -> group) and builds Jira issue payloads
from findings. Real Jira API calls are mocked for Phase 4.5; integration
tokens (D3) will be wired in a later phase.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.finding import Finding
from app.models.jira_config import JiraConfig
from app.models.project import Project
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from app.auth.middleware import AuthenticatedUser
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Severity -> Jira priority mapping (default)
_DEFAULT_PRIORITY_MAP: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraConfigService:
    """Manages Jira config resolution and issue creation (D18)."""

    # ------------------------------------------------------------------
    # Config resolution: project -> group -> None
    # ------------------------------------------------------------------

    async def resolve_config(
        self,
        org_id: uuid.UUID,
        session: AsyncSession,
        *,
        project_id: uuid.UUID | None = None,
        group_id: uuid.UUID | None = None,
    ) -> JiraConfig | None:
        """Resolve Jira config using inheritance: project -> group -> None.

        If *project_id* is given, first check for a project-level config.
        If not found, look up the project's group_id and check for a
        group-level config.  If only *group_id* is provided, look up the
        group-level config directly.
        """
        # 1) Try project-level config
        if project_id is not None:
            stmt = select(JiraConfig).where(
                JiraConfig.org_id == org_id,
                JiraConfig.scope_type == "project",
                JiraConfig.scope_id == project_id,
            )
            result = await session.execute(stmt)
            config = result.scalar_one_or_none()
            if config is not None:
                return config

            # Fall through: look up the project's group_id for group-level
            if group_id is None:
                proj_stmt = select(Project.group_id).where(Project.id == project_id)
                proj_result = await session.execute(proj_stmt)
                group_id = proj_result.scalar_one_or_none()

        # 2) Try group-level config
        if group_id is not None:
            stmt = select(JiraConfig).where(
                JiraConfig.org_id == org_id,
                JiraConfig.scope_type == "group",
                JiraConfig.scope_id == group_id,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

        return None

    # ------------------------------------------------------------------
    # Save config at group or project level
    # ------------------------------------------------------------------

    async def save_config(
        self,
        scope_type: str,
        scope_id: uuid.UUID,
        org_id: uuid.UUID,
        config_data: dict,
        session: AsyncSession,
    ) -> JiraConfig:
        """Create or update Jira config for a group or project scope."""
        stmt = select(JiraConfig).where(
            JiraConfig.org_id == org_id,
            JiraConfig.scope_type == scope_type,
            JiraConfig.scope_id == scope_id,
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            existing.project_key = config_data["jira_project_key"]
            existing.issue_type = config_data.get("default_issue_type", "Bug")
            existing.priority_mapping = config_data.get("priority_mapping", {})
            existing.custom_fields = config_data.get("custom_fields", {})
            existing.default_assignee = config_data.get("default_assignee")
            existing.labels = config_data.get("labels", [])
            await session.flush()
            return existing

        new_config = JiraConfig(
            org_id=org_id,
            scope_type=scope_type,
            scope_id=scope_id,
            project_key=config_data["jira_project_key"],
            issue_type=config_data.get("default_issue_type", "Bug"),
            priority_mapping=config_data.get("priority_mapping", {}),
            custom_fields=config_data.get("custom_fields", {}),
            default_assignee=config_data.get("default_assignee"),
            labels=config_data.get("labels", []),
        )
        session.add(new_config)
        await session.flush()
        return new_config

    # ------------------------------------------------------------------
    # Create Jira issue for a finding
    # ------------------------------------------------------------------

    async def create_issue(
        self,
        finding_id: uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Build and (mock-)send a Jira issue for a finding.

        Resolves the Jira config from the finding's project -> group hierarchy,
        constructs the payload, and returns it. The actual Jira API POST is
        mocked for Phase 4.5 — real integration comes when D3 tokens are wired.
        """
        from fastapi import HTTPException, status

        # Load finding
        stmt = select(Finding).where(Finding.id == finding_id)
        result = await session.execute(stmt)
        finding = result.scalar_one_or_none()
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found",
            )

        org_id = finding.org_id

        # Resolve config
        config = await self.resolve_config(
            org_id=org_id,
            session=session,
            project_id=finding.project_id,
        )
        if config is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No Jira configuration found for this finding's project or group",
            )

        # Build payload
        summary = f"[CipherRadar] {finding.severity.upper()}: {finding.name}"
        description = self._build_description(finding)
        priority_map = config.priority_mapping or _DEFAULT_PRIORITY_MAP
        priority = priority_map.get(finding.severity.lower(), "Medium")

        payload = {
            "fields": {
                "project": {"key": config.project_key},
                "summary": summary[:255],
                "description": description,
                "issuetype": {"name": config.issue_type},
                "priority": {"name": priority},
                "labels": list(config.labels) + [finding.severity.lower(), "cipherradar"],
            },
        }
        if config.default_assignee:
            payload["fields"]["assignee"] = {"name": config.default_assignee}
        if config.custom_fields:
            payload["fields"].update(config.custom_fields)

        # Phase 4.5: mock the Jira API call — return the constructed payload
        mock_issue_key = f"{config.project_key}-{uuid.uuid4().hex[:4].upper()}"
        mock_issue_url = f"https://jira.example.com/browse/{mock_issue_key}"

        # Store the issue URL on the finding (properties.jira_issue_url)
        props = dict(finding.properties or {})
        props["jira_issue_key"] = mock_issue_key
        props["jira_issue_url"] = mock_issue_url
        finding.properties = props
        await session.flush()

        # Audit log
        await audit_service.log(
            action_type="finding.jira_issue_created",
            user_id=actor.user_uuid,
            org_id=org_id,
            resource_type="finding",
            resource_id=finding_id,
            details={
                "issue_key": mock_issue_key,
                "issue_url": mock_issue_url,
                "jira_project_key": config.project_key,
            },
            session=session,
        )

        return {
            "issue_key": mock_issue_key,
            "issue_url": mock_issue_url,
            "summary": summary[:255],
        }

    @staticmethod
    def _build_description(finding: Finding) -> str:
        """Build a Jira issue description from a finding."""
        props = finding.properties or {}
        return (
            f"h2. Finding Summary\n"
            f"*Algorithm:* {finding.name}\n"
            f"*File:* {finding.location_file}, Line {finding.location_line}\n"
            f"*Severity:* {finding.severity}\n"
            f"*Quantum Status:* {finding.quantum_status}\n\n"
            f"h2. Details\n"
            f"*Rule ID:* {finding.rule_id}\n"
            f"*Asset Type:* {finding.asset_type}\n"
            f"*CWE:* {props.get('cwe', 'N/A')}\n\n"
            f"h2. Remediation\n"
            f"{props.get('remediation', 'See CipherRadar dashboard for remediation guidance.')}\n"
        )


# Module-level singleton
jira_config_service = JiraConfigService()
