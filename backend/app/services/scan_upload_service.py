"""Scan upload service — accepts CycloneDX CBOM JSON (ADR-025).

Handles project resolution, group resolution, finding extraction,
and scan creation from uploaded CycloneDX documents.
"""

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser
from app.models.finding import Finding
from app.models.project import Group, Project
from app.models.scan import Scan, ScanStatus


def _parse_cyclonedx(raw: bytes) -> dict[str, Any]:
    """Parse and validate CycloneDX JSON."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc

    # Basic CycloneDX validation
    bom_format = data.get("bomFormat")
    if bom_format and bom_format != "CycloneDX":
        raise HTTPException(status_code=400, detail="bomFormat must be CycloneDX")

    return data


def _parse_positive_int(value: Any) -> int | None:
    """Parse a CycloneDX numeric field into a positive key size, if possible."""
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _extract_key_size(crypto_props: dict[str, Any]) -> int | None:
    """Derive key size from CycloneDX 1.7 cryptoProperties."""
    algo_props = crypto_props.get("algorithmProperties") or {}
    if param := algo_props.get("parameterSetIdentifier"):
        if size := _parse_positive_int(param):
            return size
    if csl := algo_props.get("classicalSecurityLevel"):
        if size := _parse_positive_int(csl):
            return size
    mat_props = crypto_props.get("relatedCryptoMaterialProperties") or {}
    if mat_size := mat_props.get("size"):
        return _parse_positive_int(mat_size)
    return None


def _extract_findings_from_cyclonedx(
    cbom: dict[str, Any],
    scan_id: uuid.UUID,
    project_id: uuid.UUID,
    org_id: uuid.UUID,
) -> list[Finding]:
    """Extract Finding objects from CycloneDX components.

    Maps CycloneDX component cryptoProperties to Finding model fields.
    """
    findings: list[Finding] = []

    for comp in cbom.get("components", []):
        name = comp.get("name", "unknown")

        # Extract crypto properties (CycloneDX 1.7)
        crypto_props = comp.get("cryptoProperties", {})
        asset_type = crypto_props.get("assetType", "unknown")

        # Extract evidence/occurrences for location
        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        location_file = ""
        location_line = 0
        if occurrences:
            first = occurrences[0]
            location_file = first.get("location", "")
            location_line = first.get("line", 0)

        # Determine severity from properties or default
        properties = {}
        for prop in comp.get("properties", []):
            prop_name = prop.get("name", "")
            prop_value = prop.get("value", "")
            properties[prop_name] = prop_value

        severity = properties.get("severity", "medium")
        confidence = properties.get("confidence", "medium")
        quantum_status = properties.get("quantumStatus", "unknown")
        rule_id = properties.get("ruleId", f"upload-{name}")

        # Extract algorithm metadata from crypto properties
        algo_props = crypto_props.get("algorithmProperties", {})
        if algo_props:
            if family := algo_props.get("algorithmFamily"):
                properties["algorithm_family"] = str(family).lower()
            elif primitive := algo_props.get("primitive"):
                properties["algorithm_family"] = str(primitive).lower()

        if key_size := _extract_key_size(crypto_props):
            properties["key_size"] = key_size

        findings.append(
            Finding(
                id=uuid.uuid4(),
                scan_id=scan_id,
                project_id=project_id,
                org_id=org_id,
                rule_id=rule_id,
                name=name,
                severity=severity,
                confidence=confidence,
                quantum_status=quantum_status,
                asset_type=asset_type,
                location_file=location_file,
                location_line=location_line,
                properties=properties or None,
            )
        )

    return findings


async def _resolve_group(
    session: AsyncSession,
    org_id: uuid.UUID,
    group_path: str | None,
) -> tuple[Group | None, list[str]]:
    """Resolve group by path within an org.

    Returns (group, warnings). If group_path is None or not found,
    falls back to the first group in the org with a warning.
    """
    warnings: list[str] = []

    if group_path:
        # Try to find group by name within org
        stmt = select(Group).where(Group.org_id == org_id, Group.name == group_path)
        result = await session.execute(stmt)
        group = result.scalar_one_or_none()
        if group is not None:
            return group, warnings

        warnings.append(f"Group '{group_path}' not found, using default group")

    # Fallback to first group in org
    stmt = select(Group).where(Group.org_id == org_id).order_by(Group.created_at.asc()).limit(1)
    result = await session.execute(stmt)
    group = result.scalar_one_or_none()

    if group is None:
        raise HTTPException(status_code=404, detail="No groups found in organisation")

    if group_path:
        # Already added warning above
        pass
    else:
        warnings.append("No group_path provided, using default group")

    return group, warnings


async def _resolve_project(
    session: AsyncSession,
    org_id: uuid.UUID,
    group_id: uuid.UUID,
    project_name: str,
    user: AuthenticatedUser,
) -> tuple[Project, bool]:
    """Find or create a project by name within the org.

    Returns (project, was_created).
    Auto-creates if the user has project:write scope.
    """
    # Find existing project by name within the org
    stmt = select(Project).where(Project.org_id == org_id, Project.name == project_name)
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()

    if project is not None:
        return project, False

    # Auto-create if user has project:write scope
    if "project:write" not in user.scopes:
        raise HTTPException(
            status_code=404,
            detail=f"Project '{project_name}' not found and user lacks project:write scope to auto-create",
        )

    project = Project(
        id=uuid.uuid4(),
        group_id=group_id,
        org_id=org_id,
        name=project_name,
    )
    session.add(project)
    await session.flush()
    return project, True


async def process_scan_upload(
    session: AsyncSession,
    user: AuthenticatedUser,
    project_name: str,
    group_path: str | None,
    branch: str | None,
    commit_sha: str | None,
    cbom_raw: bytes,
) -> tuple[dict[str, Any], list[str]]:
    """Process a scan upload: parse CycloneDX, resolve project, store findings.

    Returns (result_dict, warnings).
    """
    org_id_str = user.org_id
    if not org_id_str:
        raise HTTPException(status_code=403, detail="Missing organisation context")

    org_id = uuid.UUID(org_id_str)

    # Parse CycloneDX
    cbom = _parse_cyclonedx(cbom_raw)

    # Resolve group
    group, warnings = await _resolve_group(session, org_id, group_path)
    if group is None:
        raise HTTPException(status_code=404, detail="No groups found in organisation")

    # Resolve project
    project, was_created = await _resolve_project(session, org_id, group.id, project_name, user)
    if was_created:
        warnings.append(f"Project '{project_name}' auto-created")

    # Create scan
    scan_id = uuid.uuid4()
    scan = Scan(
        id=scan_id,
        project_id=project.id,
        org_id=org_id,
        status=ScanStatus.COMPLETED,
        branch=branch,
        commit_sha=commit_sha,
        findings_count=0,
    )
    session.add(scan)
    await session.flush()

    # Extract and store findings
    findings = _extract_findings_from_cyclonedx(cbom, scan_id, project.id, org_id)
    for f in findings:
        session.add(f)

    # Update scan findings count
    scan.findings_count = len(findings)
    await session.flush()
    await session.refresh(scan)

    return {
        "scan_id": scan.id,
        "project_id": project.id,
        "project_name": project.name,
        "group_path": group.name,
        "findings_count": len(findings),
        "status": scan.status.value,
        "created_at": scan.created_at,
    }, warnings
