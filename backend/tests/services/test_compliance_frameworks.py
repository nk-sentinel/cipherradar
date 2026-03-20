"""Tests for new compliance frameworks: PCI-DSS v4, CNSA 2.0, ISO 27001, EU CRA."""

from types import SimpleNamespace

import pytest

from app.services.compliance_service import ComplianceService


def _finding(name: str, severity: str = "medium", properties: dict | None = None) -> SimpleNamespace:
    """Create a minimal finding-like object for testing."""
    return SimpleNamespace(name=name, severity=severity, properties=properties or {})


@pytest.fixture
def svc() -> ComplianceService:
    return ComplianceService()


# ---------------------------------------------------------------------------
# PCI-DSS v4.0
# ---------------------------------------------------------------------------


class TestPCIDSSv4:
    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_pci_dss_v4([])
        assert report.framework == "pci-dss-v4"
        assert report.score == 100.0
        assert report.total_findings == 0

    @pytest.mark.asyncio
    async def test_aes_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256 encryption")]
        report = await svc.evaluate_pci_dss_v4(findings)
        assert report.compliant_count == 1
        assert report.non_compliant_count == 0
        aes_item = next(i for i in report.items if i.algorithm == "aes")
        assert aes_item.classification == "compliant"

    @pytest.mark.asyncio
    async def test_des_non_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("DES encryption")]
        report = await svc.evaluate_pci_dss_v4(findings)
        assert report.non_compliant_count == 1
        des_item = next(i for i in report.items if i.algorithm == "des")
        assert des_item.classification == "non-compliant"
        assert des_item.action_required == "immediate-remediation"

    @pytest.mark.asyncio
    async def test_rc4_non_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("RC4 stream cipher")]
        report = await svc.evaluate_pci_dss_v4(findings)
        rc4_item = next(i for i in report.items if i.algorithm == "rc4")
        assert rc4_item.classification == "non-compliant"

    @pytest.mark.asyncio
    async def test_sha1_non_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("SHA-1 hash")]
        report = await svc.evaluate_pci_dss_v4(findings)
        sha1_item = next(i for i in report.items if i.algorithm == "sha1")
        assert sha1_item.classification == "non-compliant"

    @pytest.mark.asyncio
    async def test_math_random_non_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("Math.random() usage")]
        report = await svc.evaluate_pci_dss_v4(findings)
        item = next(i for i in report.items if i.algorithm == "math-random")
        assert item.classification == "non-compliant"

    @pytest.mark.asyncio
    async def test_mixed_score(self, svc: ComplianceService) -> None:
        findings = [
            _finding("AES-256"),
            _finding("SHA-256 hash"),
            _finding("DES cipher"),
        ]
        report = await svc.evaluate_pci_dss_v4(findings)
        assert report.total_findings == 3
        assert report.compliant_count == 2
        assert report.non_compliant_count == 1
        assert report.score == pytest.approx(66.7, abs=0.1)

    @pytest.mark.asyncio
    async def test_rsa_below_2048_non_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-1024", properties={"key_size": 1024})]
        report = await svc.evaluate_pci_dss_v4(findings)
        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "non-compliant"

    @pytest.mark.asyncio
    async def test_ml_kem_compliant(self, svc: ComplianceService) -> None:
        findings = [_finding("ML-KEM key encapsulation")]
        report = await svc.evaluate_pci_dss_v4(findings)
        item = next(i for i in report.items if i.algorithm == "ml-kem")
        assert item.classification == "compliant"


# ---------------------------------------------------------------------------
# CNSA 2.0
# ---------------------------------------------------------------------------


class TestCNSA2:
    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_cnsa_2([])
        assert report.framework == "cnsa-2"
        assert report.score == 100.0
        assert report.total_findings == 0

    @pytest.mark.asyncio
    async def test_aes_256_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256 encryption", properties={"key_size": 256})]
        report = await svc.evaluate_cnsa_2(findings)
        aes_item = next(i for i in report.items if i.algorithm == "aes")
        assert aes_item.classification == "approved"

    @pytest.mark.asyncio
    async def test_aes_128_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-128 encryption", properties={"key_size": 128})]
        report = await svc.evaluate_cnsa_2(findings)
        aes_item = next(i for i in report.items if i.algorithm == "aes")
        assert aes_item.classification == "not-approved"

    @pytest.mark.asyncio
    async def test_rsa_deprecated_with_deadline(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-2048", properties={"key_size": 2048})]
        report = await svc.evaluate_cnsa_2(findings)
        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "deprecated"
        assert rsa_item.action_required == "schedule-migration"
        assert "rsa" in report.migration_deadlines
        assert report.migration_deadlines["rsa"] == "2025"

    @pytest.mark.asyncio
    async def test_ml_kem_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("ML-KEM key encapsulation")]
        report = await svc.evaluate_cnsa_2(findings)
        item = next(i for i in report.items if i.algorithm == "ml-kem")
        assert item.classification == "approved"

    @pytest.mark.asyncio
    async def test_des_disallowed(self, svc: ComplianceService) -> None:
        findings = [_finding("DES cipher")]
        report = await svc.evaluate_cnsa_2(findings)
        item = next(i for i in report.items if i.algorithm == "des")
        assert item.classification == "disallowed"
        assert item.action_required == "immediate-remediation"

    @pytest.mark.asyncio
    async def test_sha256_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("SHA-256 hash")]
        report = await svc.evaluate_cnsa_2(findings)
        item = next(i for i in report.items if i.algorithm == "sha256")
        assert item.classification == "not-approved"

    @pytest.mark.asyncio
    async def test_sha384_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("SHA-384 hash")]
        report = await svc.evaluate_cnsa_2(findings)
        item = next(i for i in report.items if i.algorithm == "sha384")
        assert item.classification == "approved"

    @pytest.mark.asyncio
    async def test_ecdsa_deprecated_with_deadlines(self, svc: ComplianceService) -> None:
        findings = [_finding("ECDSA signing")]
        report = await svc.evaluate_cnsa_2(findings)
        item = next(i for i in report.items if i.algorithm == "ecdsa")
        assert item.classification == "deprecated"
        assert "ecdsa" in report.migration_deadlines

    @pytest.mark.asyncio
    async def test_mixed_score(self, svc: ComplianceService) -> None:
        findings = [
            _finding("AES-256", properties={"key_size": 256}),
            _finding("SHA-384"),
            _finding("RSA-2048", properties={"key_size": 2048}),
        ]
        report = await svc.evaluate_cnsa_2(findings)
        assert report.total_findings == 3
        assert report.compliant_count == 2
        assert report.non_compliant_count == 1
        assert report.score == pytest.approx(66.7, abs=0.1)


# ---------------------------------------------------------------------------
# ISO 27001 A.8.24
# ---------------------------------------------------------------------------


class TestISO27001A824:
    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_iso_27001_a8_24([])
        assert report.framework == "iso-27001-a8-24"
        assert report.total_checks > 0
        # Manual checks should still appear
        assert report.manual_review > 0

    @pytest.mark.asyncio
    async def test_broken_algorithm_fails_check(self, svc: ComplianceService) -> None:
        findings = [_finding("DES encryption"), _finding("AES-256")]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        # Check A.8.24-3 should fail (broken algorithms)
        check_3 = next(i for i in report.items if i.check_id == "A.8.24-3")
        assert check_3.status == "fail"
        assert "des" in check_3.evidence[0].lower()

    @pytest.mark.asyncio
    async def test_no_broken_algorithms_passes(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256"), _finding("SHA-256 hash")]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        check_3 = next(i for i in report.items if i.check_id == "A.8.24-3")
        assert check_3.status == "pass"

    @pytest.mark.asyncio
    async def test_insecure_rng_fails(self, svc: ComplianceService) -> None:
        findings = [_finding("Math.random() usage")]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        check_6 = next(i for i in report.items if i.check_id == "A.8.24-6")
        assert check_6.status == "fail"

    @pytest.mark.asyncio
    async def test_quantum_vulnerable_fails(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-2048 key exchange")]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        check_7 = next(i for i in report.items if i.check_id == "A.8.24-7")
        assert check_7.status == "fail"

    @pytest.mark.asyncio
    async def test_quantum_safe_passes(self, svc: ComplianceService) -> None:
        findings = [_finding("ML-KEM key encapsulation")]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        check_7 = next(i for i in report.items if i.check_id == "A.8.24-7")
        assert check_7.status == "pass"

    @pytest.mark.asyncio
    async def test_manual_checks_exist(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_iso_27001_a8_24([])
        manual_items = [i for i in report.items if i.status == "manual-review"]
        assert len(manual_items) > 0
        # A.8.24-1 (crypto policy) should always be manual
        check_1 = next(i for i in report.items if i.check_id == "A.8.24-1")
        assert check_1.status == "manual-review"

    @pytest.mark.asyncio
    async def test_report_has_no_score(self, svc: ComplianceService) -> None:
        """EvidenceReport should not have a 'score' field — it's a checklist."""
        report = await svc.evaluate_iso_27001_a8_24([])
        assert not hasattr(report, "score")

    @pytest.mark.asyncio
    async def test_key_size_check(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-1024", properties={"key_size": 1024})]
        report = await svc.evaluate_iso_27001_a8_24(findings)
        check_4 = next(i for i in report.items if i.check_id == "A.8.24-4")
        assert check_4.status == "fail"
        assert "inadequate" in check_4.evidence[0].lower()


# ---------------------------------------------------------------------------
# EU CRA
# ---------------------------------------------------------------------------


class TestEUCRA:
    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_eu_cra([])
        assert report.framework == "eu-cra"
        assert report.total_requirements > 0

    @pytest.mark.asyncio
    async def test_broken_algorithm_creates_gap(self, svc: ComplianceService) -> None:
        findings = [_finding("DES encryption")]
        report = await svc.evaluate_eu_cra(findings)
        # CRA-ANNEX-I-1 should have a gap
        gap_1 = next(i for i in report.items if i.requirement_id == "CRA-ANNEX-I-1")
        assert gap_1.gap_status == "gap"
        assert "des" in gap_1.affected_algorithms

    @pytest.mark.asyncio
    async def test_strong_crypto_no_gap(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256"), _finding("SHA-256 hash")]
        report = await svc.evaluate_eu_cra(findings)
        # CRA-ANNEX-I-1 should have no gap (only strong algorithms)
        gap_1 = next(i for i in report.items if i.requirement_id == "CRA-ANNEX-I-1")
        assert gap_1.gap_status == "no-gap"

    @pytest.mark.asyncio
    async def test_md5_creates_hash_gap(self, svc: ComplianceService) -> None:
        findings = [_finding("MD5 hash")]
        report = await svc.evaluate_eu_cra(findings)
        # CRA-ANNEX-I-3b (data integrity) should have a gap
        gap_3b = next(i for i in report.items if i.requirement_id == "CRA-ANNEX-I-3b")
        assert gap_3b.gap_status == "gap"
        assert "md5" in gap_3b.affected_algorithms

    @pytest.mark.asyncio
    async def test_manual_review_items(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_eu_cra([])
        manual_items = [i for i in report.items if i.gap_status == "manual-review"]
        assert len(manual_items) > 0

    @pytest.mark.asyncio
    async def test_report_has_no_score(self, svc: ComplianceService) -> None:
        """GapReport should not have a 'score' field — it's a gap analysis."""
        report = await svc.evaluate_eu_cra([])
        assert not hasattr(report, "score")

    @pytest.mark.asyncio
    async def test_gap_counts(self, svc: ComplianceService) -> None:
        findings = [_finding("DES cipher"), _finding("MD5 hash")]
        report = await svc.evaluate_eu_cra(findings)
        assert report.gaps_found > 0
        assert report.gaps_found + report.no_gaps + report.manual_review == report.total_requirements

    @pytest.mark.asyncio
    async def test_cbom_completeness_no_gap(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256")]
        report = await svc.evaluate_eu_cra(findings)
        cbom_req = next(i for i in report.items if i.requirement_id == "CRA-ANNEX-II-1")
        assert cbom_req.gap_status == "no-gap"

    @pytest.mark.asyncio
    async def test_rc4_encryption_gap(self, svc: ComplianceService) -> None:
        findings = [_finding("RC4 stream cipher")]
        report = await svc.evaluate_eu_cra(findings)
        gap_3a = next(i for i in report.items if i.requirement_id == "CRA-ANNEX-I-3a")
        assert gap_3a.gap_status == "gap"
        assert "rc4" in gap_3a.affected_algorithms
