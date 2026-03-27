"""Policy cascade service — project->group->org hierarchy with locks (D26).

Resolves effective policy by merging overrides from project, group, and org levels.
Locked rules at higher levels cannot be overridden at lower levels.
"""

from __future__ import annotations

import uuid as _uuid
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.models.policy_override import PolicyOverride
from app.models.project import Group, Project
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser


# Default built-in policy rules (from the CLI policy engine)
_DEFAULT_RULES: list[dict] = [
    {"id": "no-broken-algorithms", "severity": "critical", "enabled": True, "action": "fail"},
    {"id": "no-ecb-mode", "severity": "high", "enabled": True, "action": "fail"},
    {"id": "rsa-min-key-size", "severity": "high", "enabled": True, "action": "warn"},
    {"id": "no-deprecated-tls", "severity": "high", "enabled": True, "action": "fail"},
    {"id": "quantum-vulnerable", "severity": "medium", "enabled": True, "action": "warn"},
    {"id": "no-hardcoded-keys", "severity": "critical", "enabled": True, "action": "fail"},
]

_OA_ROLES = {"org_admin"}
_SM_ROLES = {"org_admin", "security_manager"}


class PolicyService:
    """Manages policy cascade with lock mechanism."""

    async def _load_overrides(
        self,
        org_id: str,
        session: AsyncSession,
        *,
        project_id: str | None = None,
        group_id: str | None = None,
    ) -> list[PolicyOverride]:
        """Load overrides for a specific scope (org, group, or project)."""
        stmt = select(PolicyOverride).where(
            PolicyOverride.org_id == _uuid.UUID(org_id),
        )
        if project_id is not None:
            stmt = stmt.where(PolicyOverride.project_id == _uuid.UUID(project_id))
        elif group_id is not None:
            stmt = stmt.where(
                PolicyOverride.group_id == _uuid.UUID(group_id),
                PolicyOverride.project_id.is_(None),
            )
        else:
            # Org-level: no project or group
            stmt = stmt.where(
                PolicyOverride.project_id.is_(None),
                PolicyOverride.group_id.is_(None),
            )

        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def _get_project_group_id(
        self, project_id: str, session: AsyncSession
    ) -> str | None:
        """Get the group_id for a project."""
        stmt = select(Project.group_id).where(Project.id == _uuid.UUID(project_id))
        result = await session.execute(stmt)
        gid = result.scalar_one_or_none()
        return str(gid) if gid else None

    def _merge_overrides(
        self,
        base_rules: list[dict],
        overrides: list[PolicyOverride],
    ) -> list[dict]:
        """Apply overrides on top of base rules."""
        rules_map = {r["id"]: dict(r) for r in base_rules}

        for ov in overrides:
            if ov.rule_id in rules_map:
                rules_map[ov.rule_id]["action"] = ov.action
                if ov.reason:
                    rules_map[ov.rule_id]["reason"] = ov.reason
                rules_map[ov.rule_id]["override_id"] = str(ov.id)

        return list(rules_map.values())

    def _get_locked_rules(self, overrides: list[PolicyOverride]) -> set[str]:
        """Extract rule IDs that are locked (action='lock')."""
        return {ov.rule_id for ov in overrides if ov.action == "lock"}

    async def resolve_policy(
        self,
        org_id: str,
        session: AsyncSession,
        *,
        project_id: str | None = None,
        group_id: str | None = None,
    ) -> dict:
        """Resolve effective policy using cascade: project -> group -> org.

        Locked rules at higher levels cannot be overridden at lower levels.
        """
        # 1. Start with default rules
        effective = list(_DEFAULT_RULES)

        # 2. Apply org-level overrides
        org_overrides = await self._load_overrides(org_id, session)
        effective = self._merge_overrides(effective, org_overrides)
        locked_rules = self._get_locked_rules(org_overrides)

        # 3. Apply group-level overrides (if applicable)
        effective_group_id = group_id
        if project_id and not group_id:
            effective_group_id = await self._get_project_group_id(project_id, session)

        if effective_group_id:
            group_overrides = await self._load_overrides(
                org_id, session, group_id=effective_group_id
            )
            # Filter out locked rules
            allowed_group_overrides = [
                ov for ov in group_overrides if ov.rule_id not in locked_rules
            ]
            effective = self._merge_overrides(effective, allowed_group_overrides)
            locked_rules |= self._get_locked_rules(group_overrides)

        # 4. Apply project-level overrides (if applicable)
        if project_id:
            project_overrides = await self._load_overrides(
                org_id, session, project_id=project_id
            )
            # Filter out locked rules (from org + group)
            allowed_project_overrides = [
                ov for ov in project_overrides if ov.rule_id not in locked_rules
            ]
            effective = self._merge_overrides(effective, allowed_project_overrides)

        return {
            "rules": effective,
            "locked_rules": sorted(locked_rules),
            "scope": "project" if project_id else ("group" if group_id else "org"),
        }

    async def save_policy(
        self,
        org_id: str,
        rule_id: str,
        action: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        project_id: str | None = None,
        group_id: str | None = None,
        reason: str | None = None,
    ) -> dict:
        """Save a policy override at the specified scope.

        Validates against locks at higher levels. OA can set org+locks, SM for group/project.
        """
        # RBAC check
        if project_id is None and group_id is None:
            # Org-level: OA only
            if actor.role not in _OA_ROLES:
                msg = "Only Org Admin can modify org-level policy"
                raise PermissionError(msg)
        else:
            # Group/Project level: OA or SM
            if actor.role not in _SM_ROLES:
                msg = "Only Org Admin or Security Manager can modify group/project policy"
                raise PermissionError(msg)

        # Lock enforcement: check if rule is locked at higher levels
        if project_id or group_id:
            org_overrides = await self._load_overrides(org_id, session)
            locked = self._get_locked_rules(org_overrides)

            if group_id and project_id:
                # Also check group-level locks
                group_overrides = await self._load_overrides(org_id, session, group_id=group_id)
                locked |= self._get_locked_rules(group_overrides)

            if rule_id in locked:
                msg = f"Rule '{rule_id}' is locked at a higher level and cannot be overridden"
                raise ValueError(msg)

        # Lock action only allowed for OA
        if action == "lock" and actor.role not in _OA_ROLES:
            msg = "Only Org Admin can lock policy rules"
            raise PermissionError(msg)

        # Upsert the override
        stmt = select(PolicyOverride).where(
            PolicyOverride.org_id == _uuid.UUID(org_id),
            PolicyOverride.rule_id == rule_id,
        )
        if project_id:
            stmt = stmt.where(PolicyOverride.project_id == _uuid.UUID(project_id))
        elif group_id:
            stmt = stmt.where(
                PolicyOverride.group_id == _uuid.UUID(group_id),
                PolicyOverride.project_id.is_(None),
            )
        else:
            stmt = stmt.where(
                PolicyOverride.project_id.is_(None),
                PolicyOverride.group_id.is_(None),
            )

        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.action = action
            existing.reason = reason
            existing.created_by = _uuid.UUID(actor.user_id)
        else:
            override = PolicyOverride(
                org_id=_uuid.UUID(org_id),
                project_id=_uuid.UUID(project_id) if project_id else None,
                group_id=_uuid.UUID(group_id) if group_id else None,
                framework="default",
                rule_id=rule_id,
                action=action,
                reason=reason,
                created_by=_uuid.UUID(actor.user_id),
            )
            session.add(override)

        await session.flush()

        await audit_service.log(
            action_type="policy.updated",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(org_id),
            resource_type="policy",
            details={
                "rule_id": rule_id,
                "action": action,
                "scope": "project" if project_id else ("group" if group_id else "org"),
            },
            session=session,
        )

        return {"rule_id": rule_id, "action": action, "saved": True}

    async def get_effective_rules(
        self,
        org_id: str,
        session: AsyncSession,
        *,
        project_id: str | None = None,
        group_id: str | None = None,
    ) -> list[dict]:
        """Get the effective rules after cascade resolution."""
        result = await self.resolve_policy(
            org_id, session, project_id=project_id, group_id=group_id,
        )
        return result["rules"]


policy_service = PolicyService()
