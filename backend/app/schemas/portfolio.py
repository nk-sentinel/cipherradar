"""Portfolio-level aggregation schemas for dashboard views."""

from pydantic import Field

from app.schemas.base import CamelCaseModel


class SeverityCount(CamelCaseModel):
    """A single severity bucket with its count."""

    severity: str
    count: int = Field(ge=0, default=0)


class HeatMapEntry(CamelCaseModel):
    """Single cell in the repos x severity heat map."""

    project_id: str
    project_name: str
    critical: int = Field(ge=0, default=0)
    high: int = Field(ge=0, default=0)
    medium: int = Field(ge=0, default=0)
    low: int = Field(ge=0, default=0)
    info: int = Field(ge=0, default=0)


class TopRepo(CamelCaseModel):
    """A repo ranked by risk (total weighted findings)."""

    project_id: str
    project_name: str
    total_findings: int = Field(ge=0)
    critical_count: int = Field(ge=0, default=0)
    high_count: int = Field(ge=0, default=0)
    risk_score: float = Field(ge=0, description="Weighted risk score")
    provider: str = ""
    quantum_risk: float = Field(ge=0, default=0, description="% quantum-vulnerable findings")
    compliance_percent: float = Field(ge=0, default=0, description="Avg compliance score")
    last_scan: str | None = None


class PortfolioSummary(CamelCaseModel):
    """Aggregate portfolio summary across all accessible repos."""

    total_repos: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    critical_plus_high: int = Field(ge=0, default=0)
    affected_repos: int = Field(ge=0, default=0, description="Repos with critical or high findings")
    quantum_exposed: int = Field(ge=0, default=0, description="Count of quantum-vulnerable findings")
    quantum_exposed_percent: float = Field(ge=0, le=100, default=0)
    quantum_readiness_percent: float = Field(
        ge=0, le=100, default=100, description="Percentage of findings that are quantum-safe"
    )
    compliance_avg: float = Field(ge=0, le=100, default=0)
    compliance_framework: str = ""
    last_scan_time: str | None = None
    severity_distribution: list[SeverityCount] = Field(default_factory=list)
    heat_map: list[HeatMapEntry] = Field(default_factory=list)
    top_risk_repos: list[TopRepo] = Field(default_factory=list)


class FrameworkScore(CamelCaseModel):
    """Compliance score for a single framework across all repos."""

    framework: str
    avg_score: float = Field(ge=0, le=100)
    total_compliant: int = Field(ge=0)
    total_non_compliant: int = Field(ge=0)
    repos_evaluated: int = Field(ge=0)


class PortfolioCompliance(CamelCaseModel):
    """Per-framework compliance scores across all repos."""

    frameworks: list[FrameworkScore]


class QuantumCategory(CamelCaseModel):
    """Counts for a quantum readiness category."""

    vulnerable: int = Field(ge=0, default=0)
    safe: int = Field(ge=0, default=0)
    broken: int = Field(ge=0, default=0)
    unknown: int = Field(ge=0, default=0)


class MigrationPriorityItem(CamelCaseModel):
    """An algorithm needing migration, aggregated across all repos."""

    algorithm: str
    total_count: int = Field(ge=0)
    affected_repos: int = Field(ge=0)
    migrate_to: str = Field(default="")
    priority: int = Field(ge=1)


class PortfolioQuantum(CamelCaseModel):
    """Aggregate quantum readiness across all accessible repos."""

    counts: QuantumCategory
    migration_priority: list[MigrationPriorityItem]
