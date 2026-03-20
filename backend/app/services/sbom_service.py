"""SBOM ingestion service — parse, store, and link to CBOM findings."""

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.project import Group, Project
from app.models.sbom import SBOMDocument
from app.schemas.sbom import (
    SBOMCBOMLink,
    SBOMCBOMLinkResponse,
    SBOMComponent,
    SBOMUploadResponse,
)


def _detect_sbom_format(sbom_json: dict[str, Any]) -> str:
    """Detect whether an SBOM is CycloneDX or SPDX format."""
    if "bomFormat" in sbom_json and sbom_json.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in sbom_json:
        return "spdx"
    # Heuristic: if it has "components" key, assume CycloneDX
    if "components" in sbom_json:
        return "cyclonedx"
    # If it has "packages", assume SPDX
    if "packages" in sbom_json:
        return "spdx"
    raise HTTPException(status_code=400, detail="Unrecognised SBOM format. Must be CycloneDX or SPDX JSON.")


def _extract_components_cyclonedx(sbom_json: dict[str, Any]) -> list[SBOMComponent]:
    """Extract components from a CycloneDX SBOM."""
    components: list[SBOMComponent] = []
    for comp in sbom_json.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version")
        purl = comp.get("purl")
        comp_type = comp.get("type", "library")
        if name:
            components.append(SBOMComponent(name=name, version=version, purl=purl, type=comp_type))
    return components


def _extract_components_spdx(sbom_json: dict[str, Any]) -> list[SBOMComponent]:
    """Extract components from an SPDX SBOM."""
    components: list[SBOMComponent] = []
    for pkg in sbom_json.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo")
        # SPDX uses externalRefs for purl
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        if name:
            components.append(SBOMComponent(name=name, version=version, purl=purl))
    return components


def _extract_components(sbom_json: dict[str, Any], sbom_format: str) -> list[SBOMComponent]:
    """Extract components from an SBOM based on its format."""
    if sbom_format == "cyclonedx":
        return _extract_components_cyclonedx(sbom_json)
    if sbom_format == "spdx":
        return _extract_components_spdx(sbom_json)
    return []


async def _resolve_org_id(session: AsyncSession, project_id: uuid.UUID) -> uuid.UUID:
    """Resolve org_id from project."""
    result = await session.execute(
        select(Group.org_id).join(Project, Project.group_id == Group.id).where(Project.id == project_id)
    )
    org_id = result.scalar_one_or_none()
    if org_id is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return org_id


async def upload_sbom(
    session: AsyncSession,
    project_id: uuid.UUID,
    sbom_raw: bytes,
) -> SBOMUploadResponse:
    """Parse and store an uploaded SBOM document.

    Stores SBOM via the CBOMStore pattern (inline JSONB for dev).
    """
    # Verify project exists
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    project = project_result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        sbom_json = json.loads(sbom_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON in SBOM upload") from exc

    sbom_format = _detect_sbom_format(sbom_json)
    components = _extract_components(sbom_json, sbom_format)
    org_id = await _resolve_org_id(session, project_id)

    doc_id = uuid.uuid4()
    storage_uri = f"postgres://{doc_id}"

    doc = SBOMDocument(
        id=doc_id,
        project_id=project_id,
        org_id=org_id,
        storage_uri=storage_uri,
        format=sbom_format,
        spec_version=sbom_json.get("specVersion") or sbom_json.get("spdxVersion"),
        components_count=len(components),
        sbom_json=sbom_json,
    )
    session.add(doc)
    await session.flush()

    return SBOMUploadResponse(
        sbom_id=doc_id,
        project_id=project_id,
        format=sbom_format,
        components_count=len(components),
        storage_uri=storage_uri,
    )


async def get_sbom_cbom_links(
    session: AsyncSession,
    project_id: uuid.UUID,
) -> SBOMCBOMLinkResponse:
    """Link SBOM components to CBOM findings by matching library names.

    For each SBOM component, searches CBOM findings whose name contains
    the library name (case-insensitive).
    """
    # Verify project exists
    project_stmt = select(Project).where(Project.id == project_id)
    project_result = await session.execute(project_stmt)
    if project_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get latest SBOM for the project
    sbom_stmt = (
        select(SBOMDocument)
        .where(SBOMDocument.project_id == project_id)
        .order_by(SBOMDocument.created_at.desc())
        .limit(1)
    )
    sbom_result = await session.execute(sbom_stmt)
    sbom_doc = sbom_result.scalar_one_or_none()

    if sbom_doc is None:
        raise HTTPException(status_code=404, detail="No SBOM found for this project")

    sbom_json = sbom_doc.sbom_json or {}
    sbom_format = sbom_doc.format
    components = _extract_components(sbom_json, sbom_format)

    # Get all findings for the project
    findings_stmt = select(Finding).where(Finding.project_id == project_id)
    findings_result = await session.execute(findings_stmt)
    findings = list(findings_result.scalars().all())

    # Build links
    links: list[SBOMCBOMLink] = []
    linked_count = 0

    for comp in components:
        lib_name_lower = comp.name.lower()
        matching_findings: list[str] = []

        for finding in findings:
            finding_name = (finding.name or "").lower()
            finding_file = (finding.location_file or "").lower()
            # Match if library name appears in finding name or file path
            if lib_name_lower in finding_name or lib_name_lower in finding_file:
                matching_findings.append(finding.name)

        if matching_findings:
            linked_count += 1

        links.append(
            SBOMCBOMLink(
                library_name=comp.name,
                library_version=comp.version,
                purl=comp.purl,
                crypto_findings=matching_findings,
                findings_count=len(matching_findings),
            )
        )

    return SBOMCBOMLinkResponse(
        project_id=project_id,
        total_libraries=len(components),
        linked_libraries=linked_count,
        links=links,
    )
