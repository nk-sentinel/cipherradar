"""Remediation API — LLM-assisted code fix suggestions (ADR-027).

Wired to use the DB-backed LLM config via remediation_service (D5).
Falls back to env-var-based factory when no DB config exists.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import AuthenticatedUser, get_current_user
from app.db.session import get_session
from app.models.finding import Finding
from app.schemas.remediation import (
    RemediationBatchRequest,
    RemediationBatchResponse,
    RemediationRequest,
    RemediationResponse,
)
from app.services.llm.base import CodeContext
from app.services.llm.cache import get_cached_remediation, set_cached_remediation
from app.services.llm.factory import create_llm_provider
from app.services.remediation_service import remediation_service

router = APIRouter(prefix="/remediation", tags=["remediation"])


def _build_code_context(finding: Finding) -> CodeContext:
    """Extract a CodeContext from a Finding ORM object."""
    props = finding.properties or {}
    code_data = props.get("code", {})
    code_lines = code_data.get("lines", [])
    snippet = "\n".join(code_lines) if code_lines else ""

    return CodeContext(
        language=props.get("language", "unknown"),
        file_path=finding.location_file,
        code_snippet=snippet,
        line_number=finding.location_line,
        library=props.get("library", "unknown"),
    )


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding ORM object to a plain dict for the LLM prompt."""
    props = finding.properties or {}
    return {
        "rule_id": finding.rule_id,
        "name": finding.name,
        "severity": finding.severity,
        "algorithm": props.get("algorithm"),
        "quantum_status": finding.quantum_status,
    }


async def _get_finding(session: AsyncSession, finding_id: uuid.UUID) -> Finding:
    """Load a finding by ID or raise 404."""
    stmt = select(Finding).where(Finding.id == finding_id)
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _remediate_finding(
    finding: Finding,
    *,
    use_cache: bool = True,
) -> RemediationResponse:
    """Run remediation for a single finding (with cache)."""
    context = _build_code_context(finding)
    finding_dict = _finding_to_dict(finding)

    # Check cache first
    if use_cache:
        cached = await get_cached_remediation(
            rule_id=finding.rule_id,
            file_path=finding.location_file,
            line=finding.location_line,
            code_snippet=context.code_snippet,
        )
        if cached is not None:
            return RemediationResponse(
                finding_id=finding.id,
                original_code=cached.original_code,
                fixed_code=cached.fixed_code,
                explanation=cached.explanation,
                confidence=cached.confidence,
                provider=cached.provider,
                cached=True,
            )

    # Generate via LLM
    try:
        provider = create_llm_provider()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    result = await provider.generate_remediation(finding_dict, context)

    # Cache the result
    await set_cached_remediation(
        rule_id=finding.rule_id,
        file_path=finding.location_file,
        line=finding.location_line,
        code_snippet=context.code_snippet,
        result=result,
    )

    return RemediationResponse(
        finding_id=finding.id,
        original_code=result.original_code,
        fixed_code=result.fixed_code,
        explanation=result.explanation,
        confidence=result.confidence,
        provider=result.provider,
        cached=False,
    )


@router.post(
    "/findings/{finding_id}/remediate",
    response_model=RemediationResponse,
)
async def generate_remediation(
    finding_id: uuid.UUID,
    body: RemediationRequest,
    session: AsyncSession = Depends(get_session),
    user: AuthenticatedUser | None = Depends(get_current_user),
) -> RemediationResponse:
    """Generate an LLM-assisted remediation for a single finding.

    Requires ``consent: true`` — code snippets will be sent to the configured
    LLM provider. Uses DB-backed config when available, falls back to env vars.
    """
    if not body.consent:
        raise HTTPException(
            status_code=400,
            detail="Consent is required to send code to an LLM provider. Set consent=true.",
        )

    finding = await _get_finding(session, finding_id)

    # Try DB-backed LLM config first (D5 wiring)
    if user is not None:
        try:
            result = await remediation_service.generate_fix(
                finding=finding,
                actor=user,
                session=session,
            )
            return RemediationResponse(
                finding_id=finding.id,
                original_code=result["original_code"],
                fixed_code=result["fixed_code"],
                explanation=result["explanation"],
                confidence=result["confidence"],
                provider=result["provider"],
                cached=result["cached"],
            )
        except ValueError:
            pass  # No DB config, fall back to env-var factory

    # Fallback to env-var-based factory
    return await _remediate_finding(finding)


@router.get(
    "/findings/{finding_id}/remediation",
    response_model=RemediationResponse,
)
async def get_remediation(
    finding_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> RemediationResponse:
    """Get a cached remediation for a finding (no LLM call).

    Returns 404 if no cached remediation exists.
    """
    finding = await _get_finding(session, finding_id)
    context = _build_code_context(finding)

    cached = await get_cached_remediation(
        rule_id=finding.rule_id,
        file_path=finding.location_file,
        line=finding.location_line,
        code_snippet=context.code_snippet,
    )
    if cached is None:
        raise HTTPException(
            status_code=404,
            detail="No cached remediation found for this finding",
        )

    return RemediationResponse(
        finding_id=finding.id,
        original_code=cached.original_code,
        fixed_code=cached.fixed_code,
        explanation=cached.explanation,
        confidence=cached.confidence,
        provider=cached.provider,
        cached=True,
    )


@router.post(
    "/batch",
    response_model=RemediationBatchResponse,
)
async def batch_remediate(
    body: RemediationBatchRequest,
    session: AsyncSession = Depends(get_session),
) -> RemediationBatchResponse:
    """Batch-remediate multiple findings in one request.

    Requires ``consent: true``.
    """
    if not body.consent:
        raise HTTPException(
            status_code=400,
            detail="Consent is required to send code to an LLM provider. Set consent=true.",
        )

    results: list[RemediationResponse] = []
    for fid in body.finding_ids:
        finding = await _get_finding(session, fid)
        result = await _remediate_finding(finding)
        results.append(result)

    return RemediationBatchResponse(items=results, total=len(results))
