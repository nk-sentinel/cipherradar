"""Portfolio aggregation service — cross-repo analytics with Redis caching."""

import json
import logging
import uuid
from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.portfolio import (
    FrameworkScore,
    HeatMapEntry,
    MigrationPriorityItem,
    PortfolioCompliance,
    PortfolioQuantum,
    PortfolioSummary,
    QuantumCategory,
    SeverityCount,
    TopRepo,
)
from app.services.cache_service import get_redis
from app.services.compliance_service import (
    _MIGRATION_TARGETS,
    BROKEN_FAMILIES,
    QUANTUM_SAFE_FAMILIES,
    QUANTUM_VULNERABLE_FAMILIES,
    ComplianceService,
)

logger = logging.getLogger(__name__)

# Cache TTL: 5 minutes for portfolio aggregations
# TODO: Re-enable caching with proper invalidation (bust on scan complete,
# project create/delete, finding status change). Current caching causes stale
# data — empty results cached before seed data exists, scan results not visible
# until TTL expires. See docs/PHASE-4.5-POST-IMPL-BUGS.md for details.
# When re-enabling: use cache-aside with version key or event-driven invalidation.
PORTFOLIO_CACHE_TTL = 0  # Disabled — queries are fast on indexed columns

# Severity weights for risk scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.0,
}

# All 6 compliance frameworks (4 scored + 2 checklist-based treated as pseudo-scores)
_ALL_FRAMEWORKS = [
    "nist-800-131a",
    "fips-140-3",
    "pci-dss-v4",
    "cnsa-2",
    "iso-27001-a8-24",
    "eu-cra",
]


async def _get_cached(key: str) -> dict | None:
    """Retrieve a cached portfolio result."""
    if PORTFOLIO_CACHE_TTL <= 0:
        return None  # caching disabled
    redis = get_redis()
    if redis is None:
        return None
    try:
        data = await redis.get(key)
        if data is not None:
            return json.loads(data)
    except Exception:
        logger.warning("Redis cache read failed for %s", key, exc_info=True)
    return None


async def _set_cached(key: str, data: dict) -> None:
    """Store a portfolio result in cache."""
    if PORTFOLIO_CACHE_TTL <= 0:
        return  # caching disabled
    redis = get_redis()
    if redis is None:
        return
    try:
        await redis.set(key, json.dumps(data), ex=PORTFOLIO_CACHE_TTL)
    except Exception:
        logger.warning("Redis cache write failed for %s", key, exc_info=True)


def _cache_key(user_id: str, endpoint: str) -> str:
    """Build a cache key scoped to the user (their accessible projects differ)."""
    return f"portfolio:{endpoint}:{user_id}"


async def invalidate_portfolio_cache(user_id: str) -> None:
    """Invalidate all portfolio cache entries for a user.

    Called when a new scan completes to ensure fresh data.
    """
    redis = get_redis()
    if redis is None:
        return
    try:
        for endpoint in ("summary", "compliance", "quantum"):
            key = _cache_key(user_id, endpoint)
            await redis.delete(key)
    except Exception:
        logger.warning("Redis cache invalidation failed for user %s", user_id, exc_info=True)


def _relative_time(dt: datetime) -> str:
    """Convert a datetime to a human-readable relative string."""
    now = datetime.now(UTC)
    dt_aware = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
    delta = now - dt_aware
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


async def get_portfolio_summary(
    session: AsyncSession,
    project_ids: list[uuid.UUID],
    user_id: str,
) -> PortfolioSummary:
    """Compute portfolio summary for the given project set."""
    cache_key = _cache_key(user_id, "summary")
    cached = await _get_cached(cache_key)
    if cached is not None:
        return PortfolioSummary(**cached)

    if not project_ids:
        result = PortfolioSummary(
            total_repos=0,
            total_findings=0,
            heat_map=[],
            top_risk_repos=[],
        )
        await _set_cached(cache_key, result.model_dump())
        return result

    # Fetch project names + providers
    proj_stmt = select(Project.id, Project.name, Project.provider).where(
        Project.id.in_(project_ids)
    )
    proj_result = await session.execute(proj_stmt)
    proj_rows = proj_result.fetchall()
    project_map: dict[uuid.UUID, str] = {row[0]: row[1] for row in proj_rows}
    project_provider: dict[uuid.UUID, str] = {row[0]: row[2] or "" for row in proj_rows}

    # Severity counts per project
    severity_stmt = (
        select(
            Finding.project_id,
            Finding.severity,
            func.count().label("cnt"),
        )
        .where(Finding.project_id.in_(project_ids))
        .group_by(Finding.project_id, Finding.severity)
    )
    await session.execute(text("SET LOCAL statement_timeout = '30s'"))
    severity_result = await session.execute(severity_stmt)
    severity_rows = severity_result.fetchall()

    # Build per-project severity maps
    sev_keys = ("critical", "high", "medium", "low", "info")
    project_severity: dict[uuid.UUID, dict[str, int]] = {}
    total_findings = 0
    severity_totals: dict[str, int] = {s: 0 for s in sev_keys}

    for row in severity_rows:
        pid, sev, cnt = row[0], row[1].lower(), row[2]
        total_findings += cnt
        if pid not in project_severity:
            project_severity[pid] = {s: 0 for s in sev_keys}
        if sev in project_severity[pid]:
            project_severity[pid][sev] += cnt
        if sev in severity_totals:
            severity_totals[sev] += cnt

    # Severity distribution for the bar chart
    severity_distribution = [
        SeverityCount(severity=s, count=severity_totals[s]) for s in sev_keys
    ]

    # Critical + high totals
    critical_plus_high = severity_totals["critical"] + severity_totals["high"]

    # Affected repos (repos with at least one critical or high finding)
    affected_repos = sum(
        1
        for sevs in project_severity.values()
        if sevs["critical"] > 0 or sevs["high"] > 0
    )

    # Heat map entries (per-repo, all 5 severity levels)
    heat_map: list[HeatMapEntry] = []
    for pid in project_map:
        sevs = project_severity.get(pid, {s: 0 for s in sev_keys})
        heat_map.append(
            HeatMapEntry(
                project_id=str(pid),
                project_name=project_map[pid],
                critical=sevs["critical"],
                high=sevs["high"],
                medium=sevs["medium"],
                low=sevs["low"],
                info=sevs["info"],
            )
        )

    # Quantum readiness
    quantum_stmt = (
        select(
            Finding.quantum_status,
            func.count().label("cnt"),
        )
        .where(Finding.project_id.in_(project_ids))
        .group_by(Finding.quantum_status)
    )
    quantum_result = await session.execute(quantum_stmt)
    quantum_rows = quantum_result.fetchall()

    safe_count = 0
    vulnerable_count = 0
    for row in quantum_rows:
        status = (row[0] or "").lower()
        if status in ("safe", "quantum-safe"):
            safe_count += row[1]
        elif status in ("vulnerable", "quantum-vulnerable", "broken"):
            vulnerable_count += row[1]

    quantum_readiness_pct = (
        round(100.0 * safe_count / total_findings, 1) if total_findings > 0 else 100.0
    )
    quantum_exposed_pct = (
        round(100.0 * vulnerable_count / total_findings, 1)
        if total_findings > 0
        else 0.0
    )

    # Per-project quantum vulnerability counts (for top repos)
    quantum_per_project_stmt = (
        select(
            Finding.project_id,
            func.count().label("cnt"),
        )
        .where(
            Finding.project_id.in_(project_ids),
            Finding.quantum_status.in_(["vulnerable", "broken"]),
        )
        .group_by(Finding.project_id)
    )
    qpp_result = await session.execute(quantum_per_project_stmt)
    quantum_per_project: dict[uuid.UUID, int] = {
        row[0]: row[1] for row in qpp_result.fetchall()
    }

    # Last scan time per project
    last_scan_stmt = (
        select(
            Scan.project_id,
            func.max(Scan.completed_at).label("last_completed"),
        )
        .where(Scan.project_id.in_(project_ids))
        .group_by(Scan.project_id)
    )
    last_scan_result = await session.execute(last_scan_stmt)
    last_scan_map: dict[uuid.UUID, datetime] = {}
    global_last_scan: datetime | None = None
    for row in last_scan_result.fetchall():
        if row[1] is not None:
            last_scan_map[row[0]] = row[1]
            if global_last_scan is None or row[1] > global_last_scan:
                global_last_scan = row[1]

    # Compliance: quick avg across NIST framework for summary card
    compliance_svc = ComplianceService()
    compliance_scores: list[float] = []
    # Load findings for compliance evaluation
    findings_stmt = select(Finding).where(Finding.project_id.in_(project_ids))
    findings_result = await session.execute(findings_stmt)
    all_findings = list(findings_result.scalars().all())
    project_findings: dict[uuid.UUID, list[Finding]] = {}
    for f in all_findings:
        project_findings.setdefault(f.project_id, []).append(f)

    for pid in project_ids:
        findings = project_findings.get(pid, [])
        if not findings:
            continue
        try:
            report = await compliance_svc.evaluate_nist_800_131a(findings)
            compliance_scores.append(report.score)
        except Exception:
            pass

    compliance_avg = (
        round(sum(compliance_scores) / len(compliance_scores), 1)
        if compliance_scores
        else 0.0
    )

    # Per-project compliance for top repos
    compliance_per_project: dict[uuid.UUID, float] = {}
    for pid in project_ids:
        findings = project_findings.get(pid, [])
        if not findings:
            continue
        try:
            report = await compliance_svc.evaluate_nist_800_131a(findings)
            compliance_per_project[pid] = round(report.score, 1)
        except Exception:
            pass

    # Top 10 riskiest repos
    top_repos: list[TopRepo] = []
    for pid, sevs in project_severity.items():
        total_proj_findings = sum(sevs.values())
        risk_score = sum(
            sevs[s] * _SEVERITY_WEIGHTS[s] for s in sev_keys
        )
        qv = quantum_per_project.get(pid, 0)
        quantum_risk = (
            round(100.0 * qv / total_proj_findings, 1)
            if total_proj_findings > 0
            else 0.0
        )
        ls = last_scan_map.get(pid)
        top_repos.append(
            TopRepo(
                project_id=str(pid),
                project_name=project_map.get(pid, ""),
                total_findings=total_proj_findings,
                critical_count=sevs["critical"],
                high_count=sevs["high"],
                risk_score=round(risk_score, 1),
                provider=project_provider.get(pid, ""),
                quantum_risk=quantum_risk,
                compliance_percent=compliance_per_project.get(pid, 0.0),
                last_scan=_relative_time(ls) if ls else None,
            )
        )
    top_repos.sort(key=lambda r: r.risk_score, reverse=True)
    top_repos = top_repos[:10]

    result = PortfolioSummary(
        total_repos=len(project_map),
        total_findings=total_findings,
        critical_plus_high=critical_plus_high,
        affected_repos=affected_repos,
        quantum_exposed=vulnerable_count,
        quantum_exposed_percent=quantum_exposed_pct,
        quantum_readiness_percent=quantum_readiness_pct,
        compliance_avg=compliance_avg,
        compliance_framework="NIST 800-131A",
        last_scan_time=_relative_time(global_last_scan) if global_last_scan else None,
        severity_distribution=severity_distribution,
        heat_map=heat_map,
        top_risk_repos=top_repos,
    )
    await _set_cached(cache_key, result.model_dump())
    return result


async def get_portfolio_compliance(
    session: AsyncSession,
    project_ids: list[uuid.UUID],
    user_id: str,
) -> PortfolioCompliance:
    """Compute per-framework compliance scores across all repos."""
    cache_key = _cache_key(user_id, "compliance")
    cached = await _get_cached(cache_key)
    if cached is not None:
        return PortfolioCompliance(**cached)

    if not project_ids:
        result = PortfolioCompliance(frameworks=[])
        await _set_cached(cache_key, result.model_dump())
        return result

    compliance_svc = ComplianceService()

    # Load all findings grouped by project
    findings_stmt = select(Finding).where(Finding.project_id.in_(project_ids))
    await session.execute(text("SET LOCAL statement_timeout = '30s'"))
    findings_result = await session.execute(findings_stmt)
    all_findings = list(findings_result.scalars().all())

    # Group by project
    project_findings: dict[uuid.UUID, list[Finding]] = {}
    for f in all_findings:
        project_findings.setdefault(f.project_id, []).append(f)

    framework_scores: list[FrameworkScore] = []

    for fw in _ALL_FRAMEWORKS:
        scores: list[float] = []
        total_compliant = 0
        total_non_compliant = 0
        repos_evaluated = 0

        for pid in project_ids:
            findings = project_findings.get(pid, [])
            if not findings:
                continue
            repos_evaluated += 1

            if fw == "nist-800-131a":
                report = await compliance_svc.evaluate_nist_800_131a(findings)
                scores.append(report.score)
                total_compliant += report.compliant_count
                total_non_compliant += report.non_compliant_count
            elif fw == "fips-140-3":
                report = await compliance_svc.evaluate_fips_140_3(findings)
                scores.append(report.score)
                total_compliant += report.compliant_count
                total_non_compliant += report.non_compliant_count
            elif fw == "pci-dss-v4":
                report = await compliance_svc.evaluate_pci_dss_v4(findings)
                scores.append(report.score)
                total_compliant += report.compliant_count
                total_non_compliant += report.non_compliant_count
            elif fw == "cnsa-2":
                report = await compliance_svc.evaluate_cnsa_2(findings)
                scores.append(report.score)
                total_compliant += report.compliant_count
                total_non_compliant += report.non_compliant_count
            elif fw == "iso-27001-a8-24":
                ev_report = await compliance_svc.evaluate_iso_27001_a8_24(findings)
                total_checks = ev_report.total_checks
                pseudo_score = (
                    round(100.0 * ev_report.passed / total_checks, 1) if total_checks > 0 else 100.0
                )
                scores.append(pseudo_score)
                total_compliant += ev_report.passed
                total_non_compliant += ev_report.failed
            elif fw == "eu-cra":
                gap_report = await compliance_svc.evaluate_eu_cra(findings)
                total_reqs = gap_report.total_requirements
                pseudo_score = (
                    round(100.0 * gap_report.no_gaps / total_reqs, 1) if total_reqs > 0 else 100.0
                )
                scores.append(pseudo_score)
                total_compliant += gap_report.no_gaps
                total_non_compliant += gap_report.gaps_found

        avg_score = round(sum(scores) / len(scores), 1) if scores else 100.0
        framework_scores.append(
            FrameworkScore(
                framework=fw,
                avg_score=avg_score,
                total_compliant=total_compliant,
                total_non_compliant=total_non_compliant,
                repos_evaluated=repos_evaluated,
            )
        )

    result = PortfolioCompliance(frameworks=framework_scores)
    await _set_cached(cache_key, result.model_dump())
    return result


async def get_portfolio_quantum(
    session: AsyncSession,
    project_ids: list[uuid.UUID],
    user_id: str,
) -> PortfolioQuantum:
    """Aggregate quantum readiness across all accessible repos."""
    cache_key = _cache_key(user_id, "quantum")
    cached = await _get_cached(cache_key)
    if cached is not None:
        return PortfolioQuantum(**cached)

    if not project_ids:
        result = PortfolioQuantum(
            counts=QuantumCategory(vulnerable=0, safe=0, broken=0, unknown=0),
            migration_priority=[],
        )
        await _set_cached(cache_key, result.model_dump())
        return result

    # Load findings for quantum classification
    findings_stmt = (
        select(Finding.name, Finding.properties, Finding.project_id)
        .where(Finding.project_id.in_(project_ids))
    )
    await session.execute(text("SET LOCAL statement_timeout = '30s'"))
    findings_result = await session.execute(findings_stmt)
    rows = findings_result.fetchall()

    vulnerable = 0
    safe = 0
    broken = 0
    unknown = 0

    # Track algorithms needing migration across repos
    algo_counts: Counter[str] = Counter()
    algo_repos: dict[str, set[uuid.UUID]] = {}

    for row in rows:
        name = (row[0] or "").lower()
        props = row[1] or {}
        pid = row[2]

        # Determine algorithm family (simplified from compliance_service)
        family = _extract_family_simple(name, props)

        if family in BROKEN_FAMILIES:
            broken += 1
            vulnerable += 1
            algo_counts[family] += 1
            algo_repos.setdefault(family, set()).add(pid)
        elif family in QUANTUM_VULNERABLE_FAMILIES:
            vulnerable += 1
            algo_counts[family] += 1
            algo_repos.setdefault(family, set()).add(pid)
        elif family in QUANTUM_SAFE_FAMILIES:
            safe += 1
        else:
            unknown += 1

    # Build migration priority list
    migration_priority: list[MigrationPriorityItem] = []
    priority = 1
    for algo, count in algo_counts.most_common():
        migration_priority.append(
            MigrationPriorityItem(
                algorithm=algo,
                total_count=count,
                affected_repos=len(algo_repos.get(algo, set())),
                migrate_to=_MIGRATION_TARGETS.get(algo, ""),
                priority=priority,
            )
        )
        priority += 1

    result = PortfolioQuantum(
        counts=QuantumCategory(
            vulnerable=vulnerable,
            safe=safe,
            broken=broken,
            unknown=unknown,
        ),
        migration_priority=migration_priority,
    )
    await _set_cached(cache_key, result.model_dump())
    return result


def _extract_family_simple(name: str, props: dict) -> str:
    """Extract algorithm family from finding name/props (lightweight version)."""
    if explicit := props.get("algorithm_family"):
        return str(explicit).lower().strip()

    family_keywords = [
        ("sha3-512", "sha3-512"),
        ("sha3-384", "sha3-384"),
        ("sha3-256", "sha3-256"),
        ("sha-256", "sha256"),
        ("sha256", "sha256"),
        ("sha-512", "sha512"),
        ("sha512", "sha512"),
        ("md5", "md5"),
        ("md4", "md4"),
        ("3des", "3des"),
        ("des", "des"),
        ("rc4", "rc4"),
        ("aes", "aes"),
        ("ml-kem", "ml-kem"),
        ("ml-dsa", "ml-dsa"),
        ("slh-dsa", "slh-dsa"),
        ("ecdsa", "ecdsa"),
        ("ecdh", "ecdh"),
        ("ecc", "ecc"),
        ("rsa", "rsa"),
        ("dsa", "dsa"),
        ("dh", "dh"),
    ]
    for keyword, family in family_keywords:
        if keyword in name:
            return family
    return "unknown"
