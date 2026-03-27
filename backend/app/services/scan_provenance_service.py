"""Scan provenance and environment promotion service (D21).

Handles scan provenance retrieval, environment promotion (transferring
a scan from one environment to another), and environment stage CRUD.

Usage::

    from app.services.scan_provenance_service import scan_provenance_service

    provenance = await scan_provenance_service.get_provenance(scan_id, session)
    await scan_provenance_service.promote(scan_id, "dev", "staging", actor, session)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy import select

from app.models.environment_stage import EnvironmentStage
from app.models.scan import Scan
from app.schemas.scan_provenance import (
    EnvironmentStageCreate,
    EnvironmentStageResponse,
    ProvenanceResponse,
)
from app.services.audit_service import audit_service

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.auth.middleware import AuthenticatedUser

logger = logging.getLogger(__name__)


class ScanProvenanceService:
    """Manages scan provenance and environment promotion."""

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------

    async def get_provenance(
        self,
        scan_id: uuid.UUID,
        session: AsyncSession,
    ) -> ProvenanceResponse:
        """Retrieve provenance data for a scan."""
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ProvenanceResponse(
            scan_id=scan.id,
            project_id=scan.project_id,
            branch=scan.branch,
            commit_sha=scan.commit_sha,
            tag=scan.tag,
            image_ref=scan.image_ref,
            image_digest=scan.image_digest,
            artifact_filename=scan.artifact_filename,
            artifact_checksum=scan.artifact_checksum,
            environment=scan.environment,
            promoted_at=scan.promoted_at,
            promoted_by=scan.promoted_by,
            created_at=scan.created_at,
        )

    # ------------------------------------------------------------------
    # Promotion
    # ------------------------------------------------------------------

    async def promote(
        self,
        scan_id: uuid.UUID,
        from_env: str,
        to_env: str,
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> ProvenanceResponse:
        """Promote a scan from one environment to another.

        1. Validates the scan exists and is currently in ``from_env``.
        2. Demotes any existing scan in ``to_env`` for the same project.
        3. Updates the scan's environment to ``to_env`` and records promotion metadata.
        4. Logs the action to the audit trail.
        """
        # Load scan
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Validate current environment matches from_env
        if scan.environment != from_env:
            raise HTTPException(
                status_code=400,
                detail=f"Scan is in environment '{scan.environment}', not '{from_env}'",
            )

        # Demote any existing scan in the target environment for the same project
        existing_stmt = (
            select(Scan)
            .where(Scan.project_id == scan.project_id)
            .where(Scan.environment == to_env)
            .where(Scan.id != scan_id)
        )
        existing_result = await session.execute(existing_stmt)
        for old_scan in existing_result.scalars().all():
            old_scan.environment = None
            old_scan.promoted_at = None
            old_scan.promoted_by = None

        # Promote scan
        scan.environment = to_env
        scan.promoted_at = datetime.now(timezone.utc)
        scan.promoted_by = uuid.UUID(actor.user_id)
        await session.flush()

        # Audit log
        await audit_service.log(
            action_type="scan.promote",
            user_id=uuid.UUID(actor.user_id),
            org_id=uuid.UUID(actor.org_id),
            resource_type="scan",
            resource_id=scan_id,
            details={
                "from_env": from_env,
                "to_env": to_env,
                "project_id": str(scan.project_id),
            },
            session=session,
        )

        return ProvenanceResponse(
            scan_id=scan.id,
            project_id=scan.project_id,
            branch=scan.branch,
            commit_sha=scan.commit_sha,
            tag=scan.tag,
            image_ref=scan.image_ref,
            image_digest=scan.image_digest,
            artifact_filename=scan.artifact_filename,
            artifact_checksum=scan.artifact_checksum,
            environment=scan.environment,
            promoted_at=scan.promoted_at,
            promoted_by=scan.promoted_by,
            created_at=scan.created_at,
        )

    # ------------------------------------------------------------------
    # Environment stages CRUD
    # ------------------------------------------------------------------

    async def get_environments(
        self,
        org_id: uuid.UUID,
        session: AsyncSession,
    ) -> list[EnvironmentStageResponse]:
        """List all environment stages for an org, ordered by display_order."""
        result = await session.execute(
            select(EnvironmentStage)
            .where(EnvironmentStage.org_id == org_id)
            .order_by(EnvironmentStage.display_order)
        )
        stages = result.scalars().all()
        return [EnvironmentStageResponse.model_validate(s) for s in stages]

    async def save_environments(
        self,
        org_id: uuid.UUID,
        stages: list[EnvironmentStageCreate],
        actor: AuthenticatedUser,
        session: AsyncSession,
    ) -> list[EnvironmentStageResponse]:
        """Replace all environment stages for an org.

        Deletes existing stages and creates new ones from the provided list.
        """
        # Delete existing
        existing = await session.execute(
            select(EnvironmentStage).where(EnvironmentStage.org_id == org_id)
        )
        for old in existing.scalars().all():
            await session.delete(old)
        await session.flush()

        # Create new
        new_stages: list[EnvironmentStage] = []
        for s in stages:
            stage = EnvironmentStage(
                org_id=org_id,
                name=s.name,
                display_order=s.display_order,
                color=s.color,
                is_production=s.is_production,
            )
            session.add(stage)
            new_stages.append(stage)

        await session.flush()
        for stage in new_stages:
            await session.refresh(stage)

        # Audit
        await audit_service.log(
            action_type="environments.update",
            user_id=uuid.UUID(actor.user_id),
            org_id=org_id,
            resource_type="environment_stage",
            details={"count": len(stages), "names": [s.name for s in stages]},
            session=session,
        )

        return [EnvironmentStageResponse.model_validate(s) for s in new_stages]


# Module-level singleton
scan_provenance_service = ScanProvenanceService()
