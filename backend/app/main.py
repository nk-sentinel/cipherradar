from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import health
from app.config import settings
from app.db.session import dispose_engine, init_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: initialise resources on startup, dispose on shutdown."""
    init_engine(settings.database_url)
    yield
    await dispose_engine()


def create_app(*, include_lifespan: bool = True) -> FastAPI:
    """FastAPI application factory.

    Args:
        include_lifespan: When False, skip DB/Redis initialisation.
            Useful for tests that don't need infrastructure.
    """
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        debug=settings.debug,
        lifespan=lifespan if include_lifespan else None,
    )

    # CORS — allow frontend dev server
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(health.router, prefix="/api/v1")

    return app


app = create_app()
