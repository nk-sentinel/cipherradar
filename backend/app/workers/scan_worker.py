"""Taskiq worker for executing scans (placeholder).

In production this will shell out to the ``cbom`` CLI binary
and stream results back into the database.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.db.session import get_session
from app.models.scan import Scan, ScanStatus

if TYPE_CHECKING:
    import uuid


async def run_scan(scan_id: uuid.UUID) -> None:
    """Execute a scan (placeholder implementation).

    Transitions the scan through queued -> running -> completed.
    In production, this will invoke the cbom CLI and parse results.
    """
    async for session in get_session():
        # Mark as running
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await session.execute(stmt)
        scan = result.scalar_one_or_none()

        if scan is None:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(UTC)
        await session.commit()

        # Simulate scan work
        await asyncio.sleep(1)

        # Mark as completed
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(UTC)
        await session.commit()
