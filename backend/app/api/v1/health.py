import logging

from fastapi import APIRouter

from app.schemas.health import HealthChecks, HealthResponse

router = APIRouter(tags=["health"])

logger = logging.getLogger(__name__)


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint. Returns service status, version, and dependency checks."""
    checks = HealthChecks()

    # Database connectivity check
    try:
        from app.db.session import _engine

        if _engine is not None:
            from sqlalchemy import text

            async with _engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks.database = "connected"
        else:
            checks.database = "not_initialized"
    except Exception:
        logger.warning("Database health check failed", exc_info=True)
        checks.database = "disconnected"

    # Redis connectivity check
    try:
        from app.services.cache_service import check_redis_health

        if await check_redis_health():
            checks.redis = "connected"
        else:
            checks.redis = "disconnected"
    except Exception:
        logger.warning("Redis health check failed", exc_info=True)
        checks.redis = "disconnected"

    # Overall status: ok if at least the service is running
    overall = "ok"
    if checks.database == "disconnected" and checks.redis == "disconnected":
        overall = "degraded"

    return HealthResponse(status=overall, version="0.1.0", checks=checks)
