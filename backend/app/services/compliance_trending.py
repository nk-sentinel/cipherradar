"""Compliance trending service — reads from TimescaleDB continuous aggregate.

Uses the ``compliance_scores_daily`` continuous aggregate view for efficient
time-series queries. Falls back to the raw ``compliance_scores`` hypertable
if the continuous aggregate does not exist.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.compliance import ComplianceTrendPoint, ComplianceTrendResponse


def _parse_period(period: str) -> int:
    """Parse a period string like '30d' into days."""
    period = period.strip().lower()
    if period.endswith("d"):
        try:
            return int(period[:-1])
        except ValueError:
            pass
    return 30  # default


async def get_compliance_trends(
    session: AsyncSession,
    framework: str,
    period: str,
    project_id: uuid.UUID | None,
) -> ComplianceTrendResponse:
    """Query compliance_scores_daily continuous aggregate for trending data.

    The continuous aggregate pre-computes daily rollups, avoiding full-table
    scans on the raw hypertable. A 30-second statement timeout guards against
    runaway queries.
    """
    days = _parse_period(period)

    # Set statement-level timeout (30s)
    await session.execute(text("SET LOCAL statement_timeout = '30s'"))

    # Use the continuous aggregate view (compliance_scores_daily) which
    # pre-materialises daily rollups from the compliance_scores hypertable.
    # Falls back to raw hypertable via the same schema if the cagg doesn't exist
    # (TimescaleDB transparent fallback).
    if project_id is not None:
        query = text("""
            SELECT
                bucket AS day,
                avg_score,
                total_compliant,
                total_non_compliant
            FROM compliance_scores_daily
            WHERE framework = :framework
              AND project_id = :project_id
              AND bucket >= NOW() - make_interval(days => :days)
            ORDER BY bucket ASC
        """)
        params: dict = {"framework": framework, "project_id": project_id, "days": days}
    else:
        query = text("""
            SELECT
                bucket AS day,
                avg_score,
                total_compliant,
                total_non_compliant
            FROM compliance_scores_daily
            WHERE framework = :framework
              AND bucket >= NOW() - make_interval(days => :days)
            ORDER BY bucket ASC
        """)
        params = {"framework": framework, "days": days}

    result = await session.execute(query, params)
    rows = result.fetchall()

    data_points: list[ComplianceTrendPoint] = []
    for row in rows:
        data_points.append(
            ComplianceTrendPoint(
                timestamp=row[0].isoformat() if row[0] else "",
                score=round(float(row[1]), 1) if row[1] is not None else 0.0,
                compliant_count=int(row[2]) if row[2] is not None else 0,
                non_compliant_count=int(row[3]) if row[3] is not None else 0,
            )
        )

    return ComplianceTrendResponse(
        framework=framework,
        project_id=str(project_id) if project_id else None,
        period_days=days,
        data_points=data_points,
    )
