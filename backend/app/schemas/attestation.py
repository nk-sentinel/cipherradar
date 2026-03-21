"""Pydantic schemas for CBOM attestation endpoints."""

import uuid  # noqa: TCH003 — required at runtime for Pydantic
from datetime import datetime  # noqa: TCH003 — required at runtime for Pydantic

from app.schemas.base import CamelCaseModel


class InTotoSubject(CamelCaseModel):
    """A single subject in an in-toto statement."""

    name: str
    digest: dict[str, str]


class AttestationPredicate(CamelCaseModel):
    """Predicate payload for a CBOM attestation."""

    scanner: str
    version: str
    timestamp: str
    findings_count: int
    quantum_risk_score: int
    compliance: dict[str, int]


class InTotoStatement(CamelCaseModel):
    """In-toto v1 attestation statement."""

    type: str
    subject: list[InTotoSubject]
    predicate_type: str
    predicate: AttestationPredicate


class AttestationResult(CamelCaseModel):
    """Result from creating a CBOM attestation."""

    scan_id: uuid.UUID
    attested: bool
    signature: str = ""
    certificate: str = ""
    rekor_log_id: str = ""
    in_toto_statement: InTotoStatement | None = None
    error: str = ""


class VerificationResult(CamelCaseModel):
    """Result from verifying a CBOM attestation."""

    scan_id: uuid.UUID
    verified: bool
    signer_identity: str = ""
    timestamp: str = ""
    rekor_log_id: str = ""
    error: str = ""


class AttestationMetadata(CamelCaseModel):
    """Detailed attestation metadata for a scan."""

    scan_id: uuid.UUID
    signer_identity: str = ""
    signed_at: datetime | None = None
    rekor_log_id: str = ""
    certificate: str = ""
    certificate_chain: list[str] = []
    in_toto_statement: InTotoStatement | None = None


class AttestationDownload(CamelCaseModel):
    """Signed attestation bundle for download."""

    scan_id: uuid.UUID
    bundle: dict
