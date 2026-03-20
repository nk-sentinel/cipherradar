"""Portfolio aggregation service — cross-repo analytics with Redis caching."""

import json
import logging
import uuid
from collections import Counter

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.project import Project
from app.schemas.portfolio import (
    FrameworkScore,
    HeatMapEntry,
    MigrationPriorityItem,
    PortfolioCompliance,
    PortfolioQuantum,
    PortfolioSummary,
    QuantumCategory,
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
PORTFOLIO_CACHE_TTL = 300

# Severity weights for risk scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
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
            quantum_readiness_pct=100.0,
            heat_map=[],
            top_riskiest_repos=[],
        )
        await _set_cached(cache_key, result.model_dump())
        return result

    # Fetch project names
    proj_stmt = select(Project.id, Project.name).where(Project.id.in_(project_ids))
    proj_result = await session.execute(proj_stmt)
    project_map: dict[uuid.UUID, str] = {row[0]: row[1] for row in proj_result.fetchall()}

    # Severity counts per project using statement-level timeout
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

    # Build heat map and per-project counts
    project_severity: dict[uuid.UUID, dict[str, int]] = {}
    total_findings = 0
    for row in severity_rows:
        pid, sev, cnt = row[0], row[1].lower(), row[2]
        total_findings += cnt
        if pid not in project_severity:
            project_severity[pid] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        if sev in project_severity[pid]:
            project_severity[pid][sev] += cnt

    heat_map: list[HeatMapEntry] = []
    for pid in project_map:
        sevs = project_severity.get(pid, {"critical": 0, "high": 0, "medium": 0, "low": 0})
        heat_map.append(
            HeatMapEntry(
                project_id=str(pid),
                project_name=project_map[pid],
                critical=sevs["critical"],
                high=sevs["high"],
                medium=sevs["medium"],
                low=sevs["low"],
            )
        )

    # Quantum readiness: count quantum-safe findings vs total
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
    for row in quantum_rows:
        status = row[0].lower() if row[0] else ""
        if status in ("safe", "quantum-safe"):
            safe_count += row[1]
    quantum_readiness_pct = round(100.0 * safe_count / total_findings, 1) if total_findings > 0 else 100.0

    # Top 10 riskiest repos by weighted score
    top_repos: list[TopRepo] = []
    for pid, sevs in project_severity.items():
        risk_score = (
            sevs["critical"] * _SEVERITY_WEIGHTS["critical"]
            + sevs["high"] * _SEVERITY_WEIGHTS["high"]
            + sevs["medium"] * _SEVERITY_WEIGHTS["medium"]
            + sevs["low"] * _SEVERITY_WEIGHTS["low"]
        )
        top_repos.append(
            TopRepo(
                project_id=str(pid),
                project_name=project_map.get(pid, ""),
                total_findings=sum(sevs.values()),
                critical_count=sevs["critical"],
                high_count=sevs["high"],
                risk_score=round(risk_score, 1),
            )
        )
    top_repos.sort(key=lambda r: r.risk_score, reverse=True)
    top_repos = top_repos[:10]

    result = PortfolioSummary(
        total_repos=len(project_map),
        total_findings=total_findings,
        quantum_readiness_pct=quantum_readiness_pct,
        heat_map=heat_map,
        top_riskiest_repos=top_repos,
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
