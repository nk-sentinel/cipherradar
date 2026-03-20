"""Compliance trending service — reads from compliance_scores hypertable."""

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
    """Query compliance_scores table for trending data.

    Groups scores by day and returns data points within the requested period.
    """
    days = _parse_period(period)

    if project_id is not None:
        query = text("""
            SELECT
                date_trunc('day', time) AS day,
                AVG(score) AS avg_score,
                SUM(compliant_count) AS total_compliant,
                SUM(non_compliant_count) AS total_non_compliant
            FROM compliance_scores
            WHERE framework = :framework
              AND project_id = :project_id
              AND time >= NOW() - make_interval(days => :days)
            GROUP BY day
            ORDER BY day ASC
        """)
        params = {"framework": framework, "project_id": project_id, "days": days}
    else:
        query = text("""
            SELECT
                date_trunc('day', time) AS day,
                AVG(score) AS avg_score,
                SUM(compliant_count) AS total_compliant,
                SUM(non_compliant_count) AS total_non_compliant
            FROM compliance_scores
            WHERE framework = :framework
              AND time >= NOW() - make_interval(days => :days)
            GROUP BY day
            ORDER BY day ASC
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
