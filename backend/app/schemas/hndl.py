"""HNDL (Harvest Now Decrypt Later) risk model schemas (ADR-032)."""

from pydantic import Field

from app.schemas.base import CamelCaseModel


class HNDLRisk(CamelCaseModel):
    """HNDL risk assessment for a project."""

    risk_score: float = Field(ge=0, le=1, description="Composite HNDL risk score 0-1")
    urgency: str = Field(description="URGENT / HIGH / MEDIUM / LOW")
    data_sensitivity: float = Field(ge=0, le=1)
    quantum_exposure: float = Field(ge=0, le=1)
    time_horizon: float = Field(ge=0, le=1)
    mosca_inequality: bool = Field(
        description="True if shelf_life + migration_time > quantum_timeline - current_year",
    )
    recommendations: list[str] = Field(default_factory=list)
