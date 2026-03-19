from fastapi import APIRouter

from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint. Returns service status and version."""
    return HealthResponse(status="ok", version="0.1.0")
