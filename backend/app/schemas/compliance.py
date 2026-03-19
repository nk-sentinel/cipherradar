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
