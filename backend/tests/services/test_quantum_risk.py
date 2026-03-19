"""Tests for quantum risk score computation."""

from types import SimpleNamespace

import pytest

from app.services.compliance_service import ComplianceService


def _finding(name: str, severity: str = "medium", properties: dict | None = None) -> SimpleNamespace:
    """Create a minimal finding-like object for testing."""
    return SimpleNamespace(name=name, severity=severity, properties=properties or {})


@pytest.fixture
def svc() -> ComplianceService:
    return ComplianceService()


class TestQuantumRiskScore:
    @pytest.mark.asyncio
    async def test_all_safe_score_zero(self, svc: ComplianceService) -> None:
        """All quantum-safe algorithms should produce score 0."""
        findings = [
            _finding("AES-256 encryption"),
            _finding("SHA-256 hashing"),
            _finding("ML-KEM key exchange"),
            _finding("ML-DSA digital signature"),
        ]
        result = await svc.compute_quantum_risk_score(findings)

        assert result.score == 0.0
        assert result.safe_count == 4
        assert result.vulnerable_count == 0
        assert result.broken_count == 0
        assert result.migration_items == []

    @pytest.mark.asyncio
    async def test_all_vulnerable_high_score(self, svc: ComplianceService) -> None:
        """All quantum-vulnerable algorithms should produce a high score."""
        findings = [
            _finding("RSA-2048 key exchange", severity="high"),
            _finding("ECDSA P-256 signing", severity="high"),
            _finding("ECDH key agreement", severity="high"),
        ]
        result = await svc.compute_quantum_risk_score(findings)

        assert result.score > 0
        assert result.vulnerable_count == 3
        assert result.safe_count == 0
        assert len(result.migration_items) > 0

    @pytest.mark.asyncio
    async def test_broken_algorithms_count_double(self, svc: ComplianceService) -> None:
        """Broken algorithms (DES, RC4, MD5) should contribute double risk."""
        findings_broken = [_finding("DES encryption", severity="high")]
        findings_vuln = [_finding("RSA key exchange", severity="high")]

        result_broken = await svc.compute_quantum_risk_score(findings_broken)
        result_vuln = await svc.compute_quantum_risk_score(findings_vuln)

        # Broken should have higher score than merely vulnerable (same severity)
        assert result_broken.score > result_vuln.score
        assert result_broken.broken_count == 1

    @pytest.mark.asyncio
    async def test_mixed_findings_proportional(self, svc: ComplianceService) -> None:
        """Mixed findings should produce a score between 0 and 100."""
        findings = [
            _finding("AES-256 encryption"),  # safe
            _finding("SHA-512 hashing"),  # safe
            _finding("RSA-2048 signing", severity="medium"),  # vulnerable
            _finding("DES detected", severity="high"),  # broken
        ]
        result = await svc.compute_quantum_risk_score(findings)

        assert 0 < result.score < 100
        assert result.safe_count == 2
        assert result.vulnerable_count == 2
        assert result.broken_count == 1

    @pytest.mark.asyncio
    async def test_empty_findings_score_zero(self, svc: ComplianceService) -> None:
        result = await svc.compute_quantum_risk_score([])
        assert result.score == 0.0
        assert result.vulnerable_count == 0
        assert result.safe_count == 0
        assert result.broken_count == 0

    @pytest.mark.asyncio
    async def test_deterministic_score(self, svc: ComplianceService) -> None:
        """Same findings must always produce the same score."""
        findings = [
            _finding("RSA-2048", severity="high"),
            _finding("AES-256"),
            _finding("DES detected", severity="critical"),
        ]
        result1 = await svc.compute_quantum_risk_score(findings)
        result2 = await svc.compute_quantum_risk_score(findings)
        assert result1.score == result2.score

    @pytest.mark.asyncio
    async def test_migration_items_ordered_by_priority(self, svc: ComplianceService) -> None:
        """Migration items should be sorted by priority (highest risk first)."""
        findings = [
            _finding("RSA key exchange", severity="high"),
            _finding("RSA signing", severity="high"),
            _finding("RSA encryption", severity="high"),
            _finding("ECDSA signing", severity="medium"),
        ]
        result = await svc.compute_quantum_risk_score(findings)

        assert len(result.migration_items) >= 1
        # RSA has 3 findings vs ECDSA 1, so RSA should be priority 1
        assert result.migration_items[0].algorithm == "rsa"
        assert result.migration_items[0].priority == 1

    @pytest.mark.asyncio
    async def test_migration_items_have_targets(self, svc: ComplianceService) -> None:
        """Known vulnerable algorithms should have migration targets."""
        findings = [
            _finding("RSA signing", severity="high"),
            _finding("ECDH key exchange", severity="medium"),
        ]
        result = await svc.compute_quantum_risk_score(findings)

        rsa_item = next(m for m in result.migration_items if m.algorithm == "rsa")
        assert rsa_item.migrate_to == "ml-dsa"

        ecdh_item = next(m for m in result.migration_items if m.algorithm == "ecdh")
        assert ecdh_item.migrate_to == "ml-kem"

    @pytest.mark.asyncio
    async def test_broken_algorithms_severity_critical(self, svc: ComplianceService) -> None:
        """Broken algorithms should always be severity=critical in migration items."""
        findings = [_finding("DES detected", severity="low")]
        result = await svc.compute_quantum_risk_score(findings)

        des_item = next(m for m in result.migration_items if m.algorithm == "des")
        assert des_item.severity == "critical"


class TestMigrationPriorityQueue:
    @pytest.mark.asyncio
    async def test_returns_sorted_items(self, svc: ComplianceService) -> None:
        findings = [
            _finding("RSA signing"),
            _finding("DES detected"),
            _finding("RSA encryption"),
        ]
        items = await svc.get_migration_priority_queue(findings)

        assert len(items) >= 1
        # Each item has incrementing priority
        for i, item in enumerate(items):
            assert item.priority == i + 1

    @pytest.mark.asyncio
    async def test_empty_findings_empty_queue(self, svc: ComplianceService) -> None:
        items = await svc.get_migration_priority_queue([])
        assert items == []
