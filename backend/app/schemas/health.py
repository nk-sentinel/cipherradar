from app.schemas.base import CamelCaseModel


class HealthChecks(CamelCaseModel):
    """Individual health check results."""

    database: str = "unknown"
    redis: str = "unknown"


class HealthResponse(CamelCaseModel):
    """Health check response schema."""

    status: str
    version: str
    checks: HealthChecks | None = None
