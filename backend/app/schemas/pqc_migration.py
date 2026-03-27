"""PQC migration progress schemas — post-quantum readiness tracking (D23)."""

from __future__ import annotations

from app.schemas.base import CamelCaseModel


class AlgorithmFamilyProgress(CamelCaseModel):
    """Progress of migration away from a single algorithm family."""

    family: str  # e.g. "RSA", "ECDSA", "AES", "SHA-1"
    total: int
    vulnerable: int
    safe: int
    unknown: int
    percent_migrated: float  # 0.0 – 100.0

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class LaggingProject(CamelCaseModel):
    """A project that is behind on PQC migration."""

    project_id: str
    project_name: str
    vulnerable_count: int
    total_count: int
    percent_vulnerable: float

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class MigrationOverview(CamelCaseModel):
    """High-level PQC migration percentages."""

    total_findings: int
    vulnerable: int
    safe: int
    unknown: int
    percent_vulnerable: float
    percent_safe: float
    percent_unknown: float

    model_config = {**CamelCaseModel.model_config, "from_attributes": True}


class PQCMigrationResponse(CamelCaseModel):
    """Full PQC migration progress response."""

    overview: MigrationOverview
    families: list[AlgorithmFamilyProgress]
    lagging_projects: list[LaggingProject]
