"""Taskiq worker for executing scans.

In production this will shell out to the ``cbom`` CLI binary
and stream results back into the database.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.db.session import get_session
from app.models.scan import Scan, ScanStatus
from app.services.attestation_service import _signing_enabled, attestation_service

if TYPE_CHECKING:
    import uuid

logger = logging.getLogger(__name__)

# Per-project concurrency limit: max concurrent scans per project
MAX_CONCURRENT_SCANS_PER_PROJECT = 2

# Queue timeout: max time a scan can stay queued before being marked failed
QUEUE_TIMEOUT_SECONDS = 600  # 10 minutes

# Track running scans per project for concurrency limiting
_project_semaphores: dict[str, asyncio.Semaphore] = {}


def _get_project_semaphore(project_id: str) -> asyncio.Semaphore:
    """Get or create a per-project semaphore for concurrency limiting."""
    if project_id not in _project_semaphores:
        _project_semaphores[project_id] = asyncio.Semaphore(MAX_CONCURRENT_SCANS_PER_PROJECT)
    return _project_semaphores[project_id]


async def deduplicate_scan(project_id: uuid.UUID, commit_sha: str | None) -> uuid.UUID | None:
    """Check if a scan for the same commit SHA is already queued or running.

    Returns the existing scan ID if a duplicate is found, None otherwise.
    """
    if commit_sha is None:
        return None

    async for session in get_session():
        stmt = (
            select(Scan)
            .where(
                Scan.project_id == project_id,
                Scan.commit_sha == commit_sha,
                Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING]),
            )
            .limit(1)
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing is not None:
            logger.info(
                "Duplicate scan detected for project %s, commit %s, returning existing scan %s",
                project_id,
                commit_sha,
                existing.id,
            )
            return existing.id

    return None


async def run_scan(scan_id: uuid.UUID) -> None:
    """Execute a scan with per-project concurrency limiting.

    Transitions the scan through queued -> running -> completed.
    In production, this will invoke the cbom CLI and parse results.

    Concurrency: at most MAX_CONCURRENT_SCANS_PER_PROJECT scans run
    simultaneously for any given project. Excess scans wait on a
    per-project semaphore.

    Timeout: if a scan has been queued longer than QUEUE_TIMEOUT_SECONDS,
    it is marked as failed instead of running.
    """
    async for session in get_session():
        # Load scan
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await session.execute(stmt)
        scan = result.scalar_one_or_none()

        if scan is None:
            return

        # Check queue timeout
        age = (datetime.now(UTC) - scan.created_at.replace(tzinfo=UTC)).total_seconds()
        if age > QUEUE_TIMEOUT_SECONDS:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Queue timeout exceeded ({QUEUE_TIMEOUT_SECONDS}s)"
            await session.commit()
            logger.warning("Scan %s timed out in queue after %.0fs", scan_id, age)
            return

        project_key = str(scan.project_id)
        semaphore = _get_project_semaphore(project_key)

        async with semaphore:
            # Re-load scan within semaphore (state may have changed)
            await session.refresh(scan)

            if scan.status != ScanStatus.QUEUED:
                logger.info("Scan %s is no longer queued (status=%s), skipping", scan_id, scan.status)
                return

            # Mark as running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            await session.commit()

            try:
                # Simulate scan work (placeholder)
                await asyncio.sleep(1)

                # Mark as completed
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(UTC)
                await session.commit()

                # Auto-attest if signing is enabled
                await _maybe_create_attestation(scan_id)
            except Exception:
                scan.status = ScanStatus.FAILED
                scan.error_message = "Scan execution failed"
                await session.commit()
                logger.exception("Scan %s failed", scan_id)


async def _maybe_create_attestation(scan_id: uuid.UUID) -> None:
    """Create a Sigstore attestation for a completed scan if signing is enabled.

    Reads CRADAR_SIGNING_ENABLED env var. On failure, logs a warning
    but does not fail the scan.
    """
    if not _signing_enabled():
        return

    try:
        # In production the CBOM JSON would be loaded from the CBOMStore.
        # For now, build a minimal CBOM placeholder so the attestation flow
        # can still execute end-to-end.
        cbom_placeholder = json.dumps(
            {"specVersion": "1.7", "scanId": str(scan_id)},
            indent=2,
        ).encode()

        result = await attestation_service.create_attestation(
            scan_id,
            cbom_placeholder,
        )

        if result.get("attested"):
            logger.info("Attestation created for scan %s (rekor=%s)", scan_id, result.get("rekor_log_id", ""))
        else:
            logger.warning("Attestation failed for scan %s: %s", scan_id, result.get("error", "unknown"))
    except Exception:
        logger.exception("Unexpected error creating attestation for scan %s", scan_id)
