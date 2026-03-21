"""Tests for AgilityService — 5-factor agility score computation."""

import uuid
from types import SimpleNamespace

import pytest

from app.services.agility_service import AgilityService


def _finding(
    name: str,
    location_file: str = "src/crypto.py",
    severity: str = "medium",
    properties: dict | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        severity=severity,
        location_file=location_file,
        location_line=1,
        properties=properties or {},
    )


@pytest.fixture
def svc() -> AgilityService:
    return AgilityService()


class TestCallSiteConcentration:
    """Factor 1: Call Site Concentration (20%)."""

    @pytest.mark.asyncio
    async def test_few_files_high_score(self, svc: AgilityService) -> None:
        """Crypto in <= 3 files should score 100."""
        findings = [
            _finding("AES encrypt", location_file="src/crypto.py"),
            _finding("RSA sign", location_file="src/crypto.py"),
            _finding("SHA-256 hash", location_file="src/utils.py"),
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f1 = next(f for f in score.factors if f.name == "call_site_concentration")
        assert f1.score == 100.0

    @pytest.mark.asyncio
    async def test_many_files_low_score(self, svc: AgilityService) -> None:
        """Crypto spread across 50+ files should score 0."""
        findings = [_finding("AES", location_file=f"src/file{i}.py") for i in range(55)]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f1 = next(f for f in score.factors if f.name == "call_site_concentration")
        assert f1.score == 0.0

    @pytest.mark.asyncio
    async def test_medium_files(self, svc: AgilityService) -> None:
        """4-10 files should score 75."""
        findings = [_finding("AES", location_file=f"src/file{i}.py") for i in range(7)]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f1 = next(f for f in score.factors if f.name == "call_site_concentration")
        assert f1.score == 75.0


class TestAbstractionLevel:
    """Factor 2: Abstraction Level (25%)."""

    @pytest.mark.asyncio
    async def test_all_wrapped(self, svc: AgilityService) -> None:
        """All calls through wrappers should score 100."""
        findings = [
            _finding("AES", properties={"is_wrapper": True}),
            _finding("RSA", properties={"call_depth": 2}),
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f2 = next(f for f in score.factors if f.name == "abstraction_level")
        assert f2.score == 100.0

    @pytest.mark.asyncio
    async def test_no_wrappers(self, svc: AgilityService) -> None:
        """No wrapper usage should score 0."""
        findings = [_finding("AES"), _finding("RSA")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f2 = next(f for f in score.factors if f.name == "abstraction_level")
        assert f2.score == 0.0

    @pytest.mark.asyncio
    async def test_partial_wrappers(self, svc: AgilityService) -> None:
        """Mixed wrapper usage (>70%) should score 75."""
        findings = [
            _finding("AES", properties={"is_wrapper": True}),
            _finding("RSA", properties={"is_wrapper": True}),
            _finding("SHA-256", properties={"is_wrapper": True}),
            _finding("DES"),  # direct call
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f2 = next(f for f in score.factors if f.name == "abstraction_level")
        assert f2.score == 75.0


class TestAlgorithmDiversity:
    """Factor 3: Algorithm Diversity (15%)."""

    @pytest.mark.asyncio
    async def test_low_diversity_high_score(self, svc: AgilityService) -> None:
        """1-2 unique algorithms should score 100."""
        findings = [_finding("AES-256"), _finding("AES-128")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f3 = next(f for f in score.factors if f.name == "algorithm_diversity")
        assert f3.score == 100.0

    @pytest.mark.asyncio
    async def test_high_diversity_low_score(self, svc: AgilityService) -> None:
        """20+ unique algorithms should score 0."""
        algos = [
            "AES", "RSA", "ECDSA", "ECDH", "DES", "3DES", "RC4", "MD5",
            "SHA-256", "SHA-512", "SHA-1", "SHA3-256", "SHA3-512",
            "ML-KEM", "ML-DSA", "SLH-DSA", "ChaCha20", "Blowfish",
            "DH", "DSA", "HMAC-DRBG",
        ]
        findings = [_finding(a) for a in algos]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f3 = next(f for f in score.factors if f.name == "algorithm_diversity")
        assert f3.score == 0.0


class TestKeyManagement:
    """Factor 4: Key Management Centralisation (20%)."""

    @pytest.mark.asyncio
    async def test_all_kms(self, svc: AgilityService) -> None:
        """All keys via KMS should score 100."""
        findings = [
            _finding("AES", properties={"key_management": "kms"}),
            _finding("RSA", properties={"key_management": "vault"}),
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f4 = next(f for f in score.factors if f.name == "key_management")
        assert f4.score == 100.0

    @pytest.mark.asyncio
    async def test_hardcoded_keys(self, svc: AgilityService) -> None:
        """All hardcoded keys should score 0."""
        findings = [
            _finding("AES", properties={"key_management": "hardcoded"}),
            _finding("RSA", properties={"key_management": "hardcoded"}),
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f4 = next(f for f in score.factors if f.name == "key_management")
        assert f4.score == 0.0

    @pytest.mark.asyncio
    async def test_no_key_info_defaults(self, svc: AgilityService) -> None:
        """No key management info should score 100 (nothing to penalise)."""
        findings = [_finding("AES")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f4 = next(f for f in score.factors if f.name == "key_management")
        assert f4.score == 100.0


class TestMigrationReadiness:
    """Factor 5: Migration Readiness (20%)."""

    @pytest.mark.asyncio
    async def test_all_replaceable(self, svc: AgilityService) -> None:
        """All algorithms with PQC replacements should score 100."""
        findings = [_finding("AES-256"), _finding("RSA key exchange")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        f5 = next(f for f in score.factors if f.name == "migration_readiness")
        assert f5.score == 100.0

    @pytest.mark.asyncio
    async def test_no_findings_scores_100(self, svc: AgilityService) -> None:
        """No findings should result in perfect score."""
        score = await svc.compute_score(uuid.uuid4(), [])
        assert score.total_score == 100.0
        assert score.label == "Highly Agile"


class TestCompositeScore:
    @pytest.mark.asyncio
    async def test_composite_score_range(self, svc: AgilityService) -> None:
        """Composite score should be between 0 and 100."""
        findings = [
            _finding("AES-256", location_file="src/a.py", properties={"is_wrapper": True, "key_management": "kms"}),
            _finding("RSA key", location_file="src/b.py", properties={"key_management": "config"}),
        ]
        score = await svc.compute_score(uuid.uuid4(), findings)
        assert 0 <= score.total_score <= 100

    @pytest.mark.asyncio
    async def test_five_factors_present(self, svc: AgilityService) -> None:
        """Score should always have exactly 5 factors."""
        findings = [_finding("AES")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        assert len(score.factors) == 5

    @pytest.mark.asyncio
    async def test_weights_sum_to_one(self, svc: AgilityService) -> None:
        """Factor weights should sum to 1.0."""
        findings = [_finding("AES")]
        score = await svc.compute_score(uuid.uuid4(), findings)
        total_weight = sum(f.weight for f in score.factors)
        assert total_weight == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_label_mapping(self, svc: AgilityService) -> None:
        """Label should match score tiers from ADR-031."""
        # Perfect score → Highly Agile
        score = await svc.compute_score(uuid.uuid4(), [])
        assert score.label == "Highly Agile"

    @pytest.mark.asyncio
    async def test_recommendations_for_low_score(self, svc: AgilityService) -> None:
        """Low-scoring projects should receive recommendations."""
        findings = [_finding("AES", location_file=f"src/file{i}.py") for i in range(30)]
        score = await svc.compute_score(uuid.uuid4(), findings)
        assert len(score.recommendations) > 0

    @pytest.mark.asyncio
    async def test_deterministic(self, svc: AgilityService) -> None:
        """Same findings must produce the same score."""
        pid = uuid.uuid4()
        findings = [_finding("AES"), _finding("RSA")]
        s1 = await svc.compute_score(pid, findings)
        s2 = await svc.compute_score(pid, findings)
        assert s1.total_score == s2.total_score
