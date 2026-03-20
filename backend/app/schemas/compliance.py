from pydantic import BaseModel, Field


class ComplianceItem(BaseModel):
    """A single algorithm's compliance classification within a framework."""

    algorithm: str
    classification: str = Field(description="acceptable/deprecated/disallowed (NIST) or approved/not-approved (FIPS)")
    count: int = Field(ge=0, description="Number of findings using this algorithm")
    note: str = ""
    action_required: str = Field(default="none", description="none, schedule-migration, or immediate-remediation")


class ComplianceReport(BaseModel):
    """Compliance evaluation result for a specific framework."""

    framework: str
    score: float = Field(ge=0, le=100, description="Compliance score 0-100")
    total_findings: int = Field(ge=0)
    compliant_count: int = Field(ge=0)
    non_compliant_count: int = Field(ge=0)
    items: list[ComplianceItem]
    migration_deadlines: dict[str, str] = Field(
        default_factory=dict,
        description="Per-algorithm migration deadlines (algorithm -> deadline string)",
    )


class MigrationItem(BaseModel):
    """A single algorithm that needs migration to a quantum-safe alternative."""

    algorithm: str
    count: int = Field(ge=0)
    severity: str = Field(description="critical, high, medium, low")
    migrate_to: str = Field(default="", description="Recommended replacement algorithm")
    priority: int = Field(ge=1, description="Priority rank (1 = highest)")


class QuantumRiskScore(BaseModel):
    """Quantum risk assessment for a set of cryptographic findings."""

    score: float = Field(ge=0, le=100, description="0 = fully quantum-safe, 100 = critically exposed")
    vulnerable_count: int = Field(ge=0)
    safe_count: int = Field(ge=0)
    broken_count: int = Field(ge=0, description="Algorithms already broken (DES, RC4, MD5, etc.)")
    migration_items: list[MigrationItem]


# ---------------------------------------------------------------------------
# ISO 27001 A.8.24 — Evidence Report schemas
# ---------------------------------------------------------------------------


class EvidenceItem(BaseModel):
    """A single checklist item in an ISO 27001 A.8.24 evidence report."""

    check_id: str = Field(description="Checklist item ID (e.g. A.8.24-3)")
    title: str
    description: str
    status: str = Field(description="pass, fail, manual-review, or not-applicable")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence strings")
    findings_count: int = Field(default=0, ge=0, description="Number of relevant findings")


class EvidenceReport(BaseModel):
    """ISO 27001 A.8.24 evidence-based compliance report (checklist, not score)."""

    framework: str = Field(default="iso-27001-a8-24")
    total_checks: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    manual_review: int = Field(ge=0)
    items: list[EvidenceItem]


# ---------------------------------------------------------------------------
# EU CRA — Gap Report schemas
# ---------------------------------------------------------------------------


class GapItem(BaseModel):
    """A single gap identified against an EU CRA essential requirement."""

    requirement_id: str = Field(description="CRA requirement ID (e.g. CRA-ANNEX-I-1)")
    title: str
    description: str
    gap_status: str = Field(description="gap, no-gap, or manual-review")
    affected_algorithms: list[str] = Field(default_factory=list)
    affected_count: int = Field(default=0, ge=0, description="Number of non-compliant findings")
    recommendation: str = Field(default="")


class GapReport(BaseModel):
    """EU CRA Annex I gap analysis report."""

    framework: str = Field(default="eu-cra")
    total_requirements: int = Field(ge=0)
    gaps_found: int = Field(ge=0)
    no_gaps: int = Field(ge=0)
    manual_review: int = Field(ge=0)
    items: list[GapItem]


# ---------------------------------------------------------------------------
# Compliance trending schemas
# ---------------------------------------------------------------------------


class ComplianceTrendPoint(BaseModel):
    """A single data point in a compliance trend."""

    timestamp: str = Field(description="ISO 8601 timestamp")
    score: float = Field(ge=0, le=100)
    compliant_count: int = Field(ge=0)
    non_compliant_count: int = Field(ge=0)


class ComplianceTrendResponse(BaseModel):
    """Compliance score trends over time."""

    framework: str
    project_id: str | None = None
    period_days: int
    data_points: list[ComplianceTrendPoint]
