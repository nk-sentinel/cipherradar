from pydantic import BaseModel


class HealthChecks(BaseModel):
    """Individual health check results."""

    database: str = "unknown"
    redis: str = "unknown"


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str
    version: str
    checks: HealthChecks | None = None
