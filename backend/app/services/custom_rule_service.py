"""Custom rule management service (D27).

Supports upload, fork (clone built-in), dry_run, list with filters,
and delta_sync (return rules newer than timestamp).
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import yaml
from sqlalchemy import select

from app.models.custom_rule import CustomRule
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

_OA_ROLES = {"org_admin"}
_READ_ROLES = {"org_admin", "security_manager", "security_engineer"}

# Built-in rules that can be forked
_BUILTIN_RULES: dict[str, dict] = {
    "cbom-python-md5": {
        "name": "Python MD5 usage",
        "description": "Detect MD5 hash function usage in Python",
        "language": "python",
        "pattern_type": "opengrep",
        "pattern": "rules:\n  - id: cbom-python-md5\n    pattern: hashlib.md5(...)\n    message: MD5 is broken\n    severity: WARNING",
        "severity": "high",
    },
    "cbom-java-des": {
        "name": "Java DES usage",
        "description": "Detect DES cipher usage in Java",
        "language": "java",
        "pattern_type": "opengrep",
        "pattern": 'rules:\n  - id: cbom-java-des\n    pattern: Cipher.getInstance("DES")\n    message: DES is broken\n    severity: ERROR',
        "severity": "critical",
    },
}


def validate_opengrep_rule(content: str) -> list[str]:
    """Validate YAML is a valid OpenGrep rule. Return list of errors."""
    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return [f"Invalid YAML: {e}"]

    if not isinstance(rule, dict):
        return ["Rule must be a YAML mapping"]

    errors: list[str] = []
    if "rules" not in rule:
        errors.append("Missing 'rules' key")
    else:
        for idx, r in enumerate(rule.get("rules", [])):
            if not isinstance(r, dict):
                errors.append(f"Rule at index {idx} is not a mapping")
                continue
            if "id" not in r:
                errors.append(f"Rule at index {idx} missing 'id'")
            if "pattern" not in r and "patterns" not in r:
                errors.append(f"Rule at index {idx} missing pattern")
    return errors


class CustomRuleService:
    """Manages custom detection rules for an organisation."""

    def _check_mutation_role(self, actor: AuthenticatedUser) -> None:
        """OA only for mutations."""
        if actor.role not in _OA_ROLES:
            msg = f"Role '{actor.role}' is not permitted to manage custom rules"
            raise PermissionError(msg)

    async def upload(
        self,
        name: str,
        description: str,
        language: str,
        pattern_type: str,
        pattern: str,
        severity: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Upload a new custom rule with YAML validation."""
        self._check_mutation_role(actor)

        # Validate if OpenGrep
        if pattern_type == "opengrep":
            errors = validate_opengrep_rule(pattern)
            if errors:
                msg = f"Invalid OpenGrep rule: {'; '.join(errors)}"
                raise ValueError(msg)

        rule = CustomRule(
            org_id=_uuid.UUID(actor.org_id),
            name=name,
            description=description,
            language=language.lower(),
            pattern_type=pattern_type,
            pattern=pattern,
            severity=severity,
            enabled=True,
            created_by=_uuid.UUID(actor.user_id),
        )
        session.add(rule)
        await session.flush()

        await audit_service.log(
            action_type="custom_rule.created",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="custom_rule",
            resource_id=rule.id,
            details={"name": name, "language": language, "pattern_type": pattern_type},
            session=session,
        )

        return self._rule_to_dict(rule)

    async def update(
        self,
        rule_id: _uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        name: str | None = None,
        description: str | None = None,
        pattern: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
    ) -> dict:
        """Update an existing custom rule."""
        self._check_mutation_role(actor)

        rule = await self._get_rule(rule_id, actor.org_id, session)

        if name is not None:
            rule.name = name
        if description is not None:
            rule.description = description
        if pattern is not None:
            if rule.pattern_type == "opengrep":
                errors = validate_opengrep_rule(pattern)
                if errors:
                    msg = f"Invalid OpenGrep rule: {'; '.join(errors)}"
                    raise ValueError(msg)
            rule.pattern = pattern
        if severity is not None:
            rule.severity = severity
        if enabled is not None:
            rule.enabled = enabled

        await session.flush()

        await audit_service.log(
            action_type="custom_rule.updated",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="custom_rule",
            resource_id=rule.id,
            details={"name": rule.name},
            session=session,
        )

        return self._rule_to_dict(rule)

    async def delete(
        self,
        rule_id: _uuid.UUID,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Delete a custom rule."""
        self._check_mutation_role(actor)

        rule = await self._get_rule(rule_id, actor.org_id, session)
        await session.delete(rule)
        await session.flush()

        await audit_service.log(
            action_type="custom_rule.deleted",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="custom_rule",
            resource_id=rule_id,
            details={"name": rule.name},
            session=session,
        )

        return {"id": str(rule_id), "deleted": True}

    async def fork(
        self,
        builtin_id: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Fork a built-in rule into a custom org-specific copy."""
        self._check_mutation_role(actor)

        template = _BUILTIN_RULES.get(builtin_id)
        if template is None:
            msg = f"Built-in rule '{builtin_id}' not found"
            raise ValueError(msg)

        rule = CustomRule(
            org_id=_uuid.UUID(actor.org_id),
            name=f"{template['name']} (custom)",
            description=f"Forked from built-in: {builtin_id}. {template['description']}",
            language=template["language"],
            pattern_type=template["pattern_type"],
            pattern=template["pattern"],
            severity=template["severity"],
            enabled=True,
            created_by=_uuid.UUID(actor.user_id),
        )
        session.add(rule)
        await session.flush()

        await audit_service.log(
            action_type="custom_rule.forked",
            user_id=_uuid.UUID(actor.user_id),
            org_id=_uuid.UUID(actor.org_id),
            resource_type="custom_rule",
            resource_id=rule.id,
            details={"parent_rule": builtin_id, "name": rule.name},
            session=session,
        )

        result = self._rule_to_dict(rule)
        result["parent_rule"] = builtin_id
        return result

    async def dry_run(
        self,
        rule_id: _uuid.UUID,
        test_code: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> dict:
        """Dry-run a custom rule against test code.

        Phase 4.5: returns a mock result. Real execution deferred.
        """
        rule = await self._get_rule(rule_id, actor.org_id, session)

        # Mock dry-run result for Phase 4.5
        return {
            "rule_id": str(rule_id),
            "rule_name": rule.name,
            "matches": [
                {
                    "line": 1,
                    "code": test_code.split("\n")[0] if test_code else "",
                    "message": f"Matched by rule: {rule.name}",
                }
            ],
            "match_count": 1,
        }

    async def list_rules(
        self,
        actor: AuthenticatedUser,
        session: AsyncSession,
        *,
        language: str | None = None,
        enabled: bool | None = None,
        pattern_type: str | None = None,
    ) -> list[dict]:
        """List custom rules with optional filters."""
        stmt = select(CustomRule).where(
            CustomRule.org_id == _uuid.UUID(actor.org_id),
        )
        if language:
            stmt = stmt.where(CustomRule.language == language.lower())
        if enabled is not None:
            stmt = stmt.where(CustomRule.enabled.is_(enabled))
        if pattern_type:
            stmt = stmt.where(CustomRule.pattern_type == pattern_type)

        stmt = stmt.order_by(CustomRule.created_at.desc())

        result = await session.execute(stmt)
        rules = result.scalars().all()
        return [self._rule_to_dict(r) for r in rules]

    async def delta_sync(
        self,
        since: datetime,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> list[dict]:
        """Return rules modified since a given timestamp (for CLI sync)."""
        stmt = (
            select(CustomRule)
            .where(
                CustomRule.org_id == _uuid.UUID(actor.org_id),
                CustomRule.updated_at > since,
            )
            .order_by(CustomRule.updated_at.asc())
        )
        result = await session.execute(stmt)
        rules = result.scalars().all()
        return [self._rule_to_dict(r) for r in rules]

    async def _get_rule(
        self, rule_id: _uuid.UUID, org_id: str, session: AsyncSession
    ) -> CustomRule:
        """Load a custom rule by ID or raise."""
        stmt = select(CustomRule).where(
            CustomRule.id == rule_id,
            CustomRule.org_id == _uuid.UUID(org_id),
        )
        result = await session.execute(stmt)
        rule = result.scalar_one_or_none()
        if rule is None:
            msg = f"Custom rule '{rule_id}' not found"
            raise ValueError(msg)
        return rule

    def _rule_to_dict(self, rule: CustomRule) -> dict:
        """Convert a CustomRule ORM object to a dict."""
        return {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "language": rule.language,
            "pattern_type": rule.pattern_type,
            "pattern": rule.pattern,
            "severity": rule.severity,
            "enabled": rule.enabled,
            "created_by": str(rule.created_by) if rule.created_by else None,
            "created_at": rule.created_at.isoformat() if hasattr(rule.created_at, 'isoformat') else str(rule.created_at),
            "updated_at": rule.updated_at.isoformat() if hasattr(rule.updated_at, 'isoformat') else str(rule.updated_at),
        }


custom_rule_service = CustomRuleService()
