"""Scan progress service for real-time WebSocket updates (D20 #36).

Publishes scan progress events to Redis Pub/Sub channels so that any
connected WebSocket client receives live status updates.

Usage::

    from app.services.scan_progress_service import publish_progress

    await publish_progress("scan-123", "cloning", 10, "Cloning repository")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.services.cache_service import get_redis

logger = logging.getLogger(__name__)

# Canonical progress stages with their expected percentages.
SCAN_STAGES: dict[str, int] = {
    "queued": 0,
    "cloning": 10,
    "scanning_pass1": 30,
    "scanning_pass2": 60,
    "generating_cbom": 85,
    "completed": 100,
    "failed": -1,
}


async def publish_progress(
    scan_id: str,
    status: str,
    progress_pct: int,
    detail: str = "",
) -> None:
    """Publish a scan progress event to Redis Pub/Sub.

    Parameters
    ----------
    scan_id:
        The scan UUID (as string) this progress belongs to.
    status:
        Current stage name (must be a key in ``SCAN_STAGES``).
    progress_pct:
        Integer percentage (0–100, or -1 for failure).
    detail:
        Optional human-readable detail about the current step.
    """
    redis = get_redis()
    if redis is None:
        logger.warning("Redis unavailable — scan progress not published for %s", scan_id)
        return

    payload = json.dumps({
        "scan_id": scan_id,
        "status": status,
        "progress_pct": progress_pct,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        await redis.publish(f"scan:{scan_id}", payload)
    except Exception:
        logger.warning("Failed to publish scan progress for %s", scan_id, exc_info=True)
