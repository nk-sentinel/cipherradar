"""Tests for ComplianceService — NIST SP 800-131A and FIPS 140-3 evaluation."""

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
# NIST SP 800-131A
# ---------------------------------------------------------------------------


class TestNIST800131A:
    @pytest.mark.asyncio
    async def test_des_is_disallowed(self, svc: ComplianceService) -> None:
        findings = [_finding("DES encryption detected")]
        report = await svc.evaluate_nist_800_131a(findings)

        assert report.framework == "nist-800-131a"
        assert report.non_compliant_count == 1
        assert report.compliant_count == 0

        des_item = next(i for i in report.items if i.algorithm == "des")
        assert des_item.classification == "disallowed"
        assert des_item.action_required == "immediate-remediation"

    @pytest.mark.asyncio
    async def test_aes_is_acceptable(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256 encryption")]
        report = await svc.evaluate_nist_800_131a(findings)

        assert report.compliant_count == 1
        assert report.non_compliant_count == 0

        aes_item = next(i for i in report.items if i.algorithm == "aes")
        assert aes_item.classification == "acceptable"
        assert aes_item.action_required == "none"

    @pytest.mark.asyncio
    async def test_sha1_is_disallowed(self, svc: ComplianceService) -> None:
        findings = [_finding("SHA-1 hash usage")]
        report = await svc.evaluate_nist_800_131a(findings)

        sha1_item = next(i for i in report.items if i.algorithm == "sha1")
        assert sha1_item.classification == "disallowed"
        assert sha1_item.action_required == "immediate-remediation"

    @pytest.mark.asyncio
    async def test_rsa_2048_is_deprecated(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA key exchange", properties={"key_size": 2048})]
        report = await svc.evaluate_nist_800_131a(findings)

        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "deprecated"
        assert rsa_item.action_required == "schedule-migration"

    @pytest.mark.asyncio
    async def test_rsa_1024_is_disallowed(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-1024 signing", properties={"key_size": 1024})]
        report = await svc.evaluate_nist_800_131a(findings)

        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "disallowed"

    @pytest.mark.asyncio
    async def test_md5_is_disallowed(self, svc: ComplianceService) -> None:
        findings = [_finding("MD5 hash")]
        report = await svc.evaluate_nist_800_131a(findings)

        md5_item = next(i for i in report.items if i.algorithm == "md5")
        assert md5_item.classification == "disallowed"

    @pytest.mark.asyncio
    async def test_ml_kem_is_acceptable(self, svc: ComplianceService) -> None:
        findings = [_finding("ML-KEM key encapsulation")]
        report = await svc.evaluate_nist_800_131a(findings)

        item = next(i for i in report.items if i.algorithm == "ml-kem")
        assert item.classification == "acceptable"

    @pytest.mark.asyncio
    async def test_mixed_findings_score(self, svc: ComplianceService) -> None:
        """Mixed findings: 2 acceptable + 1 disallowed + 1 deprecated."""
        findings = [
            _finding("AES-256 encryption"),
            _finding("SHA-256 hashing"),
            _finding("DES encryption detected"),
            _finding("ECDSA signing"),
        ]
        report = await svc.evaluate_nist_800_131a(findings)

        assert report.total_findings == 4
        assert report.compliant_count == 2
        assert report.non_compliant_count == 2
        assert 0 < report.score < 100

    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_nist_800_131a([])
        assert report.score == 100.0
        assert report.total_findings == 0
        assert report.items == []

    @pytest.mark.asyncio
    async def test_all_acceptable_score_100(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256"), _finding("SHA-512 hash"), _finding("ML-DSA signature")]
        report = await svc.evaluate_nist_800_131a(findings)
        assert report.score == 100.0

    @pytest.mark.asyncio
    async def test_deterministic_score(self, svc: ComplianceService) -> None:
        """Same findings must always produce the same score."""
        findings = [
            _finding("AES-256"),
            _finding("DES detected"),
            _finding("RSA-2048", properties={"key_size": 2048}),
        ]
        report1 = await svc.evaluate_nist_800_131a(findings)
        report2 = await svc.evaluate_nist_800_131a(findings)
        assert report1.score == report2.score


# ---------------------------------------------------------------------------
# FIPS 140-3
# ---------------------------------------------------------------------------


class TestFIPS1403:
    @pytest.mark.asyncio
    async def test_des_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("DES cipher")]
        report = await svc.evaluate_fips_140_3(findings)

        assert report.framework == "fips-140-3"
        des_item = next(i for i in report.items if i.algorithm == "des")
        assert des_item.classification == "not-approved"
        assert des_item.action_required == "immediate-remediation"

    @pytest.mark.asyncio
    async def test_aes_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("AES-256-GCM")]
        report = await svc.evaluate_fips_140_3(findings)

        aes_item = next(i for i in report.items if i.algorithm == "aes")
        assert aes_item.classification == "approved"
        assert aes_item.action_required == "none"

    @pytest.mark.asyncio
    async def test_rc4_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("RC4 stream cipher")]
        report = await svc.evaluate_fips_140_3(findings)

        rc4_item = next(i for i in report.items if i.algorithm == "rc4")
        assert rc4_item.classification == "not-approved"

    @pytest.mark.asyncio
    async def test_rsa_below_2048_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-1024", properties={"key_size": 1024})]
        report = await svc.evaluate_fips_140_3(findings)

        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "not-approved"

    @pytest.mark.asyncio
    async def test_rsa_2048_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("RSA-2048", properties={"key_size": 2048})]
        report = await svc.evaluate_fips_140_3(findings)

        rsa_item = next(i for i in report.items if i.algorithm == "rsa")
        assert rsa_item.classification == "approved"

    @pytest.mark.asyncio
    async def test_sha1_not_approved(self, svc: ComplianceService) -> None:
        findings = [_finding("SHA-1 signature")]
        report = await svc.evaluate_fips_140_3(findings)

        sha1_item = next(i for i in report.items if i.algorithm == "sha1")
        assert sha1_item.classification == "not-approved"

    @pytest.mark.asyncio
    async def test_score_is_percentage_compliant(self, svc: ComplianceService) -> None:
        """FIPS score = percentage of approved findings."""
        findings = [
            _finding("AES-256"),
            _finding("SHA-256 hash"),
            _finding("DES cipher"),  # not approved
        ]
        report = await svc.evaluate_fips_140_3(findings)
        # 2 approved out of 3 = ~66.7
        assert report.score == pytest.approx(66.7, abs=0.1)

    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: ComplianceService) -> None:
        report = await svc.evaluate_fips_140_3([])
        assert report.score == 100.0
        assert report.total_findings == 0
