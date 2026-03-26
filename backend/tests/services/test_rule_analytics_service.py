"""Tests for the rule effectiveness analytics service (D16)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.rule_analytics_service import RuleAnalyticsService, _parse_time_window


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RULE_ID = "cbom-python-md5-usage"
ORG_ID = uuid.uuid4()
NOW = datetime.now(UTC)


def _make_finding(
    *,
    status: str = "open",
    rule_id: str = RULE_ID,
    created_at: datetime | None = None,
) -> MagicMock:
    """Build a mock Finding object with the given status."""
    f = MagicMock()
    f.id = uuid.uuid4()
    f.rule_id = rule_id
    f.org_id = ORG_ID
    f.status = status
    f.created_at = created_at or NOW - timedelta(days=10)
    f.scan_id = uuid.uuid4()
    return f


def _mock_session_with_findings(findings: list[MagicMock]) -> AsyncMock:
    """Create a mock session that returns the given findings on first execute."""
    session = AsyncMock()

    # The first execute call returns findings via scalars().all()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = findings
    first_result = MagicMock()
    first_result.scalars.return_value = scalars_mock

    # Subsequent calls return empty lists (for MTTR and trend queries)
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    empty_result = MagicMock()
    empty_result.scalars.return_value = empty_scalars
    empty_result.all.return_value = []
    empty_result.scalar_one_or_none.return_value = None

    session.execute = AsyncMock(side_effect=[first_result, empty_result, empty_result])
    return session


# ---------------------------------------------------------------------------
# FP rate calculation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fp_rate_calculation() -> None:
    """FP rate should be (FP count / total) * 100."""
    service = RuleAnalyticsService()
    findings = [
        _make_finding(status="open"),
        _make_finding(status="false_positive"),
        _make_finding(status="false_positive"),
        _make_finding(status="resolved"),
        _make_finding(status="open"),
    ]
    session = _mock_session_with_findings(findings)

    result = await service.get_rule_analytics(
        rule_id=RULE_ID, time_window="90d", org_id=ORG_ID, session=session,
    )

    assert result.total_findings == 5
    assert result.fp_rate == 40.0  # 2/5 * 100


# ---------------------------------------------------------------------------
# Fix rate calculation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fix_rate_calculation() -> None:
    """Fix rate should be (resolved count / total) * 100."""
    service = RuleAnalyticsService()
    findings = [
        _make_finding(status="resolved"),
        _make_finding(status="resolved"),
        _make_finding(status="resolved"),
        _make_finding(status="open"),
    ]
    session = _mock_session_with_findings(findings)

    result = await service.get_rule_analytics(
        rule_id=RULE_ID, time_window="90d", org_id=ORG_ID, session=session,
    )

    assert result.total_findings == 4
    assert result.fix_rate == 75.0  # 3/4 * 100


# ---------------------------------------------------------------------------
# MTTR excludes RA and FP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mttr_excludes_ra_and_fp() -> None:
    """MTTR should only count resolved findings, not risk_accepted or false_positive."""
    service = RuleAnalyticsService()

    resolved_finding = _make_finding(status="resolved", created_at=NOW - timedelta(hours=48))
    ra_finding = _make_finding(status="risk_accepted")
    fp_finding = _make_finding(status="false_positive")
    findings = [resolved_finding, ra_finding, fp_finding]

    session = AsyncMock()

    # First call: all findings
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = findings
    first_result = MagicMock()
    first_result.scalars.return_value = scalars_mock

    # Second call (_compute_mttr): resolved findings only
    resolved_scalars = MagicMock()
    resolved_scalars.all.return_value = [resolved_finding]
    resolved_result = MagicMock()
    resolved_result.scalars.return_value = resolved_scalars

    # Third call (_compute_mttr inner): status history for resolved finding
    resolved_at = NOW - timedelta(hours=24)
    history_result = MagicMock()
    history_result.scalar_one_or_none.return_value = resolved_at

    # Fourth call (_compute_trend): empty
    empty_result = MagicMock()
    empty_result.all.return_value = []

    session.execute = AsyncMock(
        side_effect=[first_result, resolved_result, history_result, empty_result],
    )

    result = await service.get_rule_analytics(
        rule_id=RULE_ID, time_window="90d", org_id=ORG_ID, session=session,
    )

    # MTTR should be 24 hours = 86400 seconds
    assert result.mttr_seconds is not None
    assert abs(result.mttr_seconds - 86400.0) < 1.0  # allow small float variance

    # Verify FP and RA are counted but not in MTTR
    assert result.fp_rate == pytest.approx(33.33, abs=0.1)
    assert result.ra_rate == pytest.approx(33.33, abs=0.1)


# ---------------------------------------------------------------------------
# Time window filtering (30d)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_time_window_filtering_30d() -> None:
    """30d time window should be parsed and used in the query."""
    service = RuleAnalyticsService()

    # No findings (empty result)
    findings: list[MagicMock] = []
    session = _mock_session_with_findings(findings)

    result = await service.get_rule_analytics(
        rule_id=RULE_ID, time_window="30d", org_id=ORG_ID, session=session,
    )

    assert result.time_window == "30d"
    assert result.total_findings == 0


# ---------------------------------------------------------------------------
# Warning flag: high FP rate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_warning_flag_high_fp_rate() -> None:
    """Rules summary should set warning=True when fp_rate > 50."""
    service = RuleAnalyticsService()
    session = AsyncMock()

    # Simulate aggregate query result
    row = MagicMock()
    row.rule_id = RULE_ID
    row.total = 10
    row.fp_count = 6  # 60% FP rate
    row.resolved_count = 3

    agg_result = MagicMock()
    agg_result.all.return_value = [row]
    session.execute = AsyncMock(return_value=agg_result)

    summaries = await service.get_rules_summary(
        org_id=ORG_ID, time_window="90d", session=session,
    )

    assert len(summaries) == 1
    assert summaries[0].warning is True
    assert summaries[0].fp_rate == 60.0


# ---------------------------------------------------------------------------
# Trend returns per-scan counts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trend_returns_per_scan_counts() -> None:
    """Trend data should return one entry per scan with count and timestamp."""
    service = RuleAnalyticsService()

    scan_id_1 = uuid.uuid4()
    scan_id_2 = uuid.uuid4()
    scan_time_1 = NOW - timedelta(days=5)
    scan_time_2 = NOW - timedelta(days=2)

    findings = [
        _make_finding(status="open"),
        _make_finding(status="open"),
    ]

    session = AsyncMock()

    # First call: findings
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = findings
    first_result = MagicMock()
    first_result.scalars.return_value = scalars_mock

    # Second call (_compute_mttr): no resolved findings
    empty_scalars = MagicMock()
    empty_scalars.all.return_value = []
    mttr_result = MagicMock()
    mttr_result.scalars.return_value = empty_scalars

    # Third call (_compute_trend): scan trend data
    trend_row_1 = MagicMock()
    trend_row_1.scan_id = scan_id_1
    trend_row_1.count = 3
    trend_row_1.scanned_at = scan_time_1

    trend_row_2 = MagicMock()
    trend_row_2.scan_id = scan_id_2
    trend_row_2.count = 1
    trend_row_2.scanned_at = scan_time_2

    trend_result = MagicMock()
    trend_result.all.return_value = [trend_row_1, trend_row_2]

    session.execute = AsyncMock(
        side_effect=[first_result, mttr_result, trend_result],
    )

    result = await service.get_rule_analytics(
        rule_id=RULE_ID, time_window="90d", org_id=ORG_ID, session=session,
    )

    assert len(result.trend) == 2
    assert result.trend[0].scan_id == scan_id_1
    assert result.trend[0].count == 3
    assert result.trend[1].scan_id == scan_id_2
    assert result.trend[1].count == 1


# ---------------------------------------------------------------------------
# _parse_time_window
# ---------------------------------------------------------------------------


def test_parse_time_window_valid() -> None:
    """Valid '30d' format should return correct timedelta."""
    assert _parse_time_window("30d") == timedelta(days=30)
    assert _parse_time_window("90d") == timedelta(days=90)
    assert _parse_time_window("7d") == timedelta(days=7)


def test_parse_time_window_invalid_defaults_90d() -> None:
    """Invalid format should default to 90 days."""
    assert _parse_time_window("invalid") == timedelta(days=90)
    assert _parse_time_window("") == timedelta(days=90)
