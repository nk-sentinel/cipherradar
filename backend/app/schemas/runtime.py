"""Runtime enrichment schemas for OpenTelemetry observations (ADR-028)."""

import uuid
from datetime import datetime

from pydantic import Field

from app.schemas.base import CamelCaseModel


class RuntimeObservation(CamelCaseModel):
    """A single runtime TLS/cipher observation from an OTel exporter."""

    service_name: str = Field(description="Service emitting the observation")
    tls_version: str | None = Field(default=None, description="TLS version negotiated (e.g. 1.2, 1.3)")
    cipher_suite: str | None = Field(default=None, description="Cipher suite negotiated (e.g. TLS_AES_256_GCM_SHA384)")
    peer_cert_subject: str | None = Field(default=None, description="Peer certificate subject DN")
    timestamp: datetime = Field(description="When the observation was recorded")
    project_id: uuid.UUID = Field(description="Project this observation belongs to")


class RuntimeObservationBatch(CamelCaseModel):
    """Batch of runtime observations from an OTel exporter."""

    observations: list[RuntimeObservation]


class EnrichedFinding(CamelCaseModel):
    """A static finding enriched with runtime observation data."""

    finding_id: uuid.UUID
    rule_id: str
    name: str
    severity: str
    location_file: str
    location_line: int
    runtime_observed: bool = Field(
        default=False,
        description="Whether this finding was observed at runtime",
    )
    observed_tls_version: str | None = Field(
        default=None,
        description="TLS version observed at runtime (if different from static finding)",
    )
    observed_cipher: str | None = Field(
        default=None,
        description="Cipher suite observed at runtime",
    )
    mismatch: bool = Field(
        default=False,
        description="True if runtime observation differs from static finding",
    )


class RuntimeSummary(CamelCaseModel):
    """Summary of runtime observations across all services in a project."""

    project_id: uuid.UUID
    total_observations: int = Field(ge=0)
    unique_tls_versions: list[str] = Field(default_factory=list)
    unique_cipher_suites: list[str] = Field(default_factory=list)
    services_observed: list[str] = Field(default_factory=list)
    mismatches: int = Field(
        default=0,
        ge=0,
        description="Number of configured-vs-observed mismatches",
    )
