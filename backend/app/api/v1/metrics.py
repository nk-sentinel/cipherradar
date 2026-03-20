"""Prometheus metrics endpoint — counters, gauges, and histograms.

Exposes application metrics in Prometheus text exposition format at
``GET /api/v1/metrics``.
"""

import logging
import time

from fastapi import APIRouter, Response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

# ---------------------------------------------------------------------------
# Metric storage
#
# Lightweight in-process storage. In production with multiple replicas,
# each instance exposes its own /metrics endpoint and Prometheus scrapes
# all of them — no cross-instance aggregation needed here.
# ---------------------------------------------------------------------------

# Counters (monotonically increasing)
_counters: dict[str, float] = {
    "scans_total": 0,
    "scans_completed_total": 0,
    "scans_failed_total": 0,
    "findings_total": 0,
    "findings_critical_total": 0,
    "findings_high_total": 0,
    "findings_medium_total": 0,
    "findings_low_total": 0,
    "notifications_sent_total": 0,
    "notifications_sent_email_total": 0,
    "notifications_sent_teams_total": 0,
    "notifications_sent_inapp_total": 0,
}

# Gauges (can go up or down)
_gauges: dict[str, float] = {
    "active_scans": 0,
    "queue_depth": 0,
    "portfolio_quantum_risk_score": 0.0,
}

# Histograms — store raw observations, compute buckets at scrape time
_histogram_observations: dict[str, list[float]] = {
    "scan_duration_seconds": [],
    "api_response_duration_seconds": [],
}

# Histogram bucket boundaries
SCAN_DURATION_BUCKETS = [10, 30, 60, 120, 300, 600, 1200, 3600]
API_RESPONSE_BUCKETS = [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

_HISTOGRAM_BUCKETS: dict[str, list[float]] = {
    "scan_duration_seconds": SCAN_DURATION_BUCKETS,
    "api_response_duration_seconds": API_RESPONSE_BUCKETS,
}

# Maximum observations to keep in memory per histogram (ring buffer)
_MAX_OBSERVATIONS = 10000


# ---------------------------------------------------------------------------
# Public API for recording metrics from other modules
# ---------------------------------------------------------------------------


def inc_counter(name: str, value: float = 1.0) -> None:
    """Increment a counter metric."""
    if name in _counters:
        _counters[name] += value


def set_gauge(name: str, value: float) -> None:
    """Set a gauge metric to an absolute value."""
    if name in _gauges:
        _gauges[name] = value


def observe_histogram(name: str, value: float) -> None:
    """Record an observation for a histogram metric."""
    if name in _histogram_observations:
        obs = _histogram_observations[name]
        if len(obs) >= _MAX_OBSERVATIONS:
            obs.pop(0)
        obs.append(value)


class ScanTimer:
    """Context manager for timing scan duration."""

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        elapsed = time.monotonic() - self._start
        observe_histogram("scan_duration_seconds", elapsed)


class APITimer:
    """Context manager for timing API response duration."""

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        elapsed = time.monotonic() - self._start
        observe_histogram("api_response_duration_seconds", elapsed)


# ---------------------------------------------------------------------------
# Prometheus text format rendering
# ---------------------------------------------------------------------------


def _render_counter(name: str, value: float, help_text: str) -> str:
    """Render a single counter in Prometheus exposition format."""
    return f"# HELP {name} {help_text}\n# TYPE {name} counter\n{name} {value}\n"


def _render_gauge(name: str, value: float, help_text: str) -> str:
    """Render a single gauge in Prometheus exposition format."""
    return f"# HELP {name} {help_text}\n# TYPE {name} gauge\n{name} {value}\n"


def _render_histogram(name: str, observations: list[float], buckets: list[float], help_text: str) -> str:
    """Render a histogram in Prometheus exposition format."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} histogram"]

    total = len(observations)
    total_sum = sum(observations) if observations else 0.0

    for boundary in buckets:
        count = sum(1 for o in observations if o <= boundary)
        lines.append(f'{name}_bucket{{le="{boundary}"}} {count}')

    lines.append(f'{name}_bucket{{le="+Inf"}} {total}')
    lines.append(f"{name}_sum {total_sum}")
    lines.append(f"{name}_count {total}")

    return "\n".join(lines) + "\n"


def render_metrics() -> str:
    """Render all metrics in Prometheus text exposition format."""
    parts: list[str] = []

    # Counters
    counter_help = {
        "scans_total": "Total number of scans initiated.",
        "scans_completed_total": "Total number of scans completed successfully.",
        "scans_failed_total": "Total number of scans that failed.",
        "findings_total": "Total number of findings detected.",
        "findings_critical_total": "Total critical-severity findings.",
        "findings_high_total": "Total high-severity findings.",
        "findings_medium_total": "Total medium-severity findings.",
        "findings_low_total": "Total low-severity findings.",
        "notifications_sent_total": "Total notifications sent across all channels.",
        "notifications_sent_email_total": "Total email notifications sent.",
        "notifications_sent_teams_total": "Total Teams notifications sent.",
        "notifications_sent_inapp_total": "Total in-app notifications sent.",
    }
    for name, value in _counters.items():
        parts.append(_render_counter(name, value, counter_help.get(name, "")))

    # Gauges
    gauge_help = {
        "active_scans": "Number of currently running scans.",
        "queue_depth": "Number of scans waiting in the queue.",
        "portfolio_quantum_risk_score": "Organisation-level quantum readiness risk score (0-100).",
    }
    for name, value in _gauges.items():
        parts.append(_render_gauge(name, value, gauge_help.get(name, "")))

    # Histograms
    histogram_help = {
        "scan_duration_seconds": "Distribution of scan execution times in seconds.",
        "api_response_duration_seconds": "Distribution of API response times in seconds.",
    }
    for name, observations in _histogram_observations.items():
        buckets = _HISTOGRAM_BUCKETS.get(name, [])
        parts.append(_render_histogram(name, observations, buckets, histogram_help.get(name, "")))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    """Prometheus-format metrics endpoint.

    Returns all application metrics in Prometheus text exposition format.
    """
    body = render_metrics()
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
