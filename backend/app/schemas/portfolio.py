"""Portfolio-level aggregation schemas for dashboard views."""

from pydantic import BaseModel, Field


class HeatMapEntry(BaseModel):
    """Single cell in the repos x severity heat map."""

    project_id: str
    project_name: str
    critical: int = Field(ge=0, default=0)
    high: int = Field(ge=0, default=0)
    medium: int = Field(ge=0, default=0)
    low: int = Field(ge=0, default=0)


class TopRepo(BaseModel):
    """A repo ranked by risk (total weighted findings)."""

    project_id: str
    project_name: str
    total_findings: int = Field(ge=0)
    critical_count: int = Field(ge=0, default=0)
    high_count: int = Field(ge=0, default=0)
    risk_score: float = Field(ge=0, description="Weighted risk score")


class PortfolioSummary(BaseModel):
    """Aggregate portfolio summary across all accessible repos."""

    total_repos: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    quantum_readiness_pct: float = Field(
        ge=0, le=100, description="Percentage of findings that are quantum-safe"
    )
    heat_map: list[HeatMapEntry]
    top_riskiest_repos: list[TopRepo]


class FrameworkScore(BaseModel):
    """Compliance score for a single framework across all repos."""

    framework: str
    avg_score: float = Field(ge=0, le=100)
    total_compliant: int = Field(ge=0)
    total_non_compliant: int = Field(ge=0)
    repos_evaluated: int = Field(ge=0)


class PortfolioCompliance(BaseModel):
    """Per-framework compliance scores across all repos."""

    frameworks: list[FrameworkScore]


class QuantumCategory(BaseModel):
    """Counts for a quantum readiness category."""

    vulnerable: int = Field(ge=0, default=0)
    safe: int = Field(ge=0, default=0)
    broken: int = Field(ge=0, default=0)
    unknown: int = Field(ge=0, default=0)


class MigrationPriorityItem(BaseModel):
    """An algorithm needing migration, aggregated across all repos."""

    algorithm: str
    total_count: int = Field(ge=0)
    affected_repos: int = Field(ge=0)
    migrate_to: str = Field(default="")
    priority: int = Field(ge=1)


class PortfolioQuantum(BaseModel):
    """Aggregate quantum readiness across all accessible repos."""

    counts: QuantumCategory
    migration_priority: list[MigrationPriorityItem]
