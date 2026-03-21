"""CBOM attestation API endpoints — metadata, verify, and download."""

import logging
import uuid

from fastapi import APIRouter, HTTPException, status

from app.schemas.attestation import (
    AttestationDownload,
    AttestationMetadata,
    VerificationResult,
)
from app.services.attestation_service import attestation_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attestation"])


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/attestation — get attestation metadata
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/attestation",
    response_model=AttestationMetadata,
)
async def get_attestation(scan_id: uuid.UUID) -> AttestationMetadata:
    """Get attestation metadata for a scan.

    Returns signer identity, timestamp, Rekor entry, certificate chain,
    and the full in-toto statement.
    """
    result = await attestation_service.get_attestation_metadata(scan_id)

    if "error" in result:
        error = result["error"]
        if "not found" in error.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=error,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error,
        )

    statement = result.get("in_toto_statement")
    in_toto = None
    if statement is not None:
        # Build nested schema from raw dict
        from app.schemas.attestation import (
            AttestationPredicate,
            InTotoStatement,
            InTotoSubject,
        )

        predicate_raw = statement.get("predicate", {})
        subjects_raw = statement.get("subject", [])

        in_toto = InTotoStatement(
            type=statement.get("_type", ""),
            subject=[
                InTotoSubject(name=s["name"], digest=s["digest"])
                for s in subjects_raw
            ],
            predicate_type=statement.get("predicateType", ""),
            predicate=AttestationPredicate(
                scanner=predicate_raw.get("scanner", ""),
                version=predicate_raw.get("version", ""),
                timestamp=predicate_raw.get("timestamp", ""),
                findings_count=predicate_raw.get("findings_count", 0),
                quantum_risk_score=predicate_raw.get("quantum_risk_score", 0),
                compliance=predicate_raw.get("compliance", {}),
            ),
        )

    return AttestationMetadata(
        scan_id=scan_id,
        signer_identity=result.get("signer_identity", ""),
        signed_at=result.get("signed_at"),
        rekor_log_id=result.get("rekor_log_id", ""),
        certificate=result.get("certificate", ""),
        certificate_chain=result.get("certificate_chain", []),
        in_toto_statement=in_toto,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/attestation/verify — verify attestation
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/attestation/verify",
    response_model=VerificationResult,
)
async def verify_attestation(scan_id: uuid.UUID) -> VerificationResult:
    """Verify a CBOM attestation via cosign verify-blob-attestation."""
    result = await attestation_service.verify_attestation(scan_id)

    if not result.get("verified", False) and "error" in result:
        error = result["error"]
        if "not found" in error.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=error,
            )

    return VerificationResult(
        scan_id=scan_id,
        verified=result.get("verified", False),
        signer_identity=result.get("signer_identity", ""),
        timestamp=result.get("timestamp", ""),
        rekor_log_id=result.get("rekor_log_id", ""),
        error=result.get("error", ""),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/attestation/download — download bundle
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/attestation/download",
    response_model=AttestationDownload,
)
async def download_attestation(scan_id: uuid.UUID) -> AttestationDownload:
    """Download the signed attestation bundle for a scan.

    Returns the full Sigstore bundle including signature, certificate,
    and in-toto statement.
    """
    result = await attestation_service.get_attestation_metadata(scan_id)

    if "error" in result:
        error = result["error"]
        if "not found" in error.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=error,
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error,
        )

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "verificationMaterial": {
            "certificate": result.get("certificate", ""),
            "certificateChain": result.get("certificate_chain", []),
            "tlogEntries": [
                {
                    "logId": result.get("rekor_log_id", ""),
                },
            ],
        },
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": result.get("in_toto_statement"),
            "signatures": [
                {
                    "sig": result.get("certificate", ""),
                    "keyid": "",
                },
            ],
        },
    }

    return AttestationDownload(
        scan_id=scan_id,
        bundle=bundle,
    )
