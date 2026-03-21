"""Cryptographic Agility Score schemas (ADR-031)."""

from pydantic import Field

from app.schemas.base import CamelCaseModel


class FactorScore(CamelCaseModel):
    """Score for a single agility factor."""

    name: str = Field(description="Factor name (e.g. call_site_concentration)")
    weight: float = Field(ge=0, le=1, description="Factor weight (0-1)")
    score: float = Field(ge=0, le=100, description="Factor score (0-100)")
    details: str = Field(default="", description="Human-readable explanation")


class AgilityScore(CamelCaseModel):
    """Composite cryptographic agility score for a project."""

    total_score: float = Field(ge=0, le=100, description="Composite agility score 0-100")
    label: str = Field(description="Highly Agile / Moderately Agile / Limited Agility / Rigid")
    factors: list[FactorScore]
    recommendations: list[str] = Field(default_factory=list)
