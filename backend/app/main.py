from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.logging_config import setup_logging

from app.api.v1 import (
    admin,
    agility,
    api_keys,
    artifact_registries,
    assets,
    attestation,
    auth,
    bulk_actions,
    cbom,
    certificate_tracker,
    compliance,
    custom_rules,
    deptrack,
    finding_requests,
    finding_status,
    health,
    hndl,
    integrations,
    jira,
    metrics,
    notifications,
    password,
    policy,
    portfolio,
    pqc_migration,
    projects,
    remediation,
    reports,
    rule_analytics,
    runtime,
    sbom,
    scan_provenance,
    scan_schedule,
    scan_upload,
    scans,
    signing,
    user,
    webhooks,
    ws,
)
from app.config import settings
from app.db.session import dispose_engine, init_engine
from app.services.cache_service import close_redis, init_redis

logger = logging.getLogger(__name__)


async def _lookup_user_by_email(email: str):
    """Database-backed user lookup for auth module."""
    from sqlalchemy import text

    from app.db.session import get_session

    async for session in get_session():
        result = await session.execute(
            text("SELECT id, email, hashed_password, role, is_active, org_id FROM users WHERE email = :email"),
            {"email": email},
        )
        row = result.fetchone()
        if row is None:
            return None
        return {
            "id": str(row[0]),
            "email": row[1],
            "hashed_password": row[2],
            "role": row[3],
            "is_active": row[4],
            "org_id": str(row[5]),
        }
    return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: initialise resources on startup, dispose on shutdown."""
    setup_logging(settings.log_level)
    logger.info("Starting CipherRadar backend", extra={"extra_fields": {"version": "0.1.0"}})
    init_engine(settings.database_url)
    await init_redis()
    # Wire auth callbacks to real database
    auth.set_user_lookup(_lookup_user_by_email)
    yield
    logger.info("Shutting down CipherRadar backend")
    await close_redis()
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
        allow_origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next) -> Response:  # noqa: ANN001
        start = time.time()
        response: Response = await call_next(request)
        duration_ms = (time.time() - start) * 1000
        # Skip noisy health-check logs
        if request.url.path != "/api/v1/health":
            logger.info(
                "Request completed",
                extra={"extra_fields": {
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                }},
            )
        return response

    # Routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(cbom.router, prefix="/api/v1")
    app.include_router(webhooks.router, prefix="/api/v1")
    app.include_router(integrations.router, prefix="/api/v1")
    app.include_router(compliance.router, prefix="/api/v1")
    app.include_router(compliance.trends_router, prefix="/api/v1")
    app.include_router(sbom.router, prefix="/api/v1")
    app.include_router(scan_upload.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(notifications.router, prefix="/api/v1")
    app.include_router(jira.router, prefix="/api/v1")
    app.include_router(signing.router, prefix="/api/v1")
    app.include_router(attestation.router, prefix="/api/v1")
    app.include_router(ws.router, prefix="/api/v1")
    app.include_router(portfolio.router, prefix="/api/v1")
    app.include_router(deptrack.router, prefix="/api/v1")
    app.include_router(metrics.router, prefix="/api/v1")
    app.include_router(projects.router, prefix="/api/v1")
    app.include_router(projects.repos_router, prefix="/api/v1")
    app.include_router(policy.router, prefix="/api/v1")
    app.include_router(admin.router, prefix="/api/v1")
    app.include_router(assets.router, prefix="/api/v1")
    app.include_router(remediation.router, prefix="/api/v1")
    app.include_router(runtime.router, prefix="/api/v1")
    app.include_router(agility.router, prefix="/api/v1")
    app.include_router(hndl.router, prefix="/api/v1")
    app.include_router(user.router, prefix="/api/v1")
    app.include_router(finding_status.router, prefix="/api/v1")
    app.include_router(finding_requests.router, prefix="/api/v1")
    app.include_router(bulk_actions.router, prefix="/api/v1")
    app.include_router(rule_analytics.router, prefix="/api/v1")
    app.include_router(scan_schedule.router, prefix="/api/v1")
    app.include_router(scan_provenance.router, prefix="/api/v1")
    app.include_router(artifact_registries.router, prefix="/api/v1")
    app.include_router(password.router, prefix="/api/v1")
    app.include_router(api_keys.router, prefix="/api/v1")
    app.include_router(certificate_tracker.router, prefix="/api/v1")
    app.include_router(pqc_migration.router, prefix="/api/v1")
    app.include_router(custom_rules.router, prefix="/api/v1")

    return app


app = create_app()
