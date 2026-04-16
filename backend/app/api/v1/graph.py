"""Crypto dependency graph API endpoint."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.models.finding import Finding

logger = logging.getLogger(__name__)

router = APIRouter(tags=["graph"])


@router.get("/graph")
async def get_graph(
    user: AuthenticatedUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Return crypto dependency graph data derived from findings.

    Nodes = unique algorithm/protocol/certificate findings.
    Links = findings in the same file or project.
    """
    stmt = select(Finding).where(Finding.org_id == user.required_org_uuid).limit(500)
    result = await session.execute(stmt)
    findings = result.scalars().all()

    if not findings:
        return {"nodes": [], "links": []}

    nodes = []
    seen = set()
    for f in findings:
        key = f"{f.name}:{f.asset_type}"
        if key in seen:
            continue
        seen.add(key)
        nodes.append({
            "id": str(f.id),
            "name": f.name,
            "type": f.asset_type,
            "language": (f.properties or {}).get("language", "Unknown"),
            "quantumStatus": f.quantum_status,
            "severity": f.severity,
        })

    # Simple links: connect findings in same file
    links = []
    file_groups: dict[str, list[str]] = {}
    for f in findings:
        file_groups.setdefault(f.location_file, []).append(str(f.id))

    for file_ids in file_groups.values():
        if len(file_ids) > 1:
            for i in range(len(file_ids) - 1):
                if file_ids[i] in seen and file_ids[i + 1] in seen:
                    links.append({"source": file_ids[i], "target": file_ids[i + 1]})

    logger.info("Graph data", extra={"extra_fields": {"nodes": len(nodes), "links": len(links)}})
    return {"nodes": nodes[:200], "links": links[:500]}
