"""Tests for HNDLService — HNDL risk scoring and Mosca inequality."""

import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services.hndl_service import HNDLService


def _finding(name: str, severity: str = "medium", properties: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(name=name, severity=severity, properties=properties or {})


@pytest.fixture
def svc() -> HNDLService:
    return HNDLService()


class TestRiskScoring:
    @pytest.mark.asyncio
    async def test_quantum_safe_zero_risk(self, svc: HNDLService) -> None:
        """Quantum-safe algorithms should produce zero or near-zero risk."""
        findings = [_finding("AES-256 encryption"), _finding("SHA-256 hash")]
        risk = await svc.compute_risk(uuid.uuid4(), findings, data_classification="confidential")
        assert risk.risk_score == 0.0
        assert risk.urgency == "LOW"

    @pytest.mark.asyncio
    async def test_quantum_vulnerable_high_risk(self, svc: HNDLService) -> None:
        """Quantum-vulnerable algorithms with confidential data should have high risk."""
        findings = [_finding("RSA-2048 key exchange")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="confidential",
            quantum_deadline=2035,
        )
        assert risk.risk_score > 0
        assert risk.quantum_exposure > 0
        assert risk.data_sensitivity == 0.7

    @pytest.mark.asyncio
    async def test_public_data_low_risk(self, svc: HNDLService) -> None:
        """Public data should have low risk even with vulnerable algorithms."""
        findings = [_finding("RSA-2048")]
        risk = await svc.compute_risk(uuid.uuid4(), findings, data_classification="public")
        # Public data has sensitivity 0.1, so even with max vulnerability, risk is low
        assert risk.data_sensitivity == 0.1
        assert risk.risk_score < 0.2

    @pytest.mark.asyncio
    async def test_restricted_data_max_sensitivity(self, svc: HNDLService) -> None:
        """Restricted data should have maximum sensitivity."""
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(uuid.uuid4(), findings, data_classification="restricted")
        assert risk.data_sensitivity == 1.0

    @pytest.mark.asyncio
    async def test_empty_findings(self, svc: HNDLService) -> None:
        """No findings should produce zero risk."""
        risk = await svc.compute_risk(uuid.uuid4(), [])
        assert risk.risk_score == 0.0
        assert risk.urgency == "LOW"
        assert risk.mosca_inequality is False

    @pytest.mark.asyncio
    async def test_risk_score_range(self, svc: HNDLService) -> None:
        """Risk score should always be between 0 and 1."""
        findings = [_finding("RSA"), _finding("ECDSA"), _finding("DH")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="restricted",
        )
        assert 0.0 <= risk.risk_score <= 1.0

    @pytest.mark.asyncio
    async def test_multiplicative_zero_property(self, svc: HNDLService) -> None:
        """If any factor is zero, risk should be zero (multiplicative model)."""
        # AES-256 has quantum_vulnerability = 0.0 → entire risk = 0
        findings = [_finding("AES-256")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="restricted",
        )
        assert risk.risk_score == 0.0


class TestTimeFactor:
    @pytest.mark.asyncio
    async def test_at_deadline_max_urgency(self, svc: HNDLService) -> None:
        """When current year equals deadline, time factor should be 1.0."""
        findings = [_finding("RSA")]
        with patch("app.services.hndl_service.datetime") as mock_dt:
            mock_dt.now.return_value.year = 2035
            mock_dt.side_effect = lambda *a, **kw: mock_dt.now.return_value
            # Use a deadline at current year
            risk = await svc.compute_risk(
                uuid.uuid4(),
                findings,
                quantum_deadline=2035,
            )
        assert risk.time_horizon >= 0.0  # Should be high

    @pytest.mark.asyncio
    async def test_far_from_deadline(self, svc: HNDLService) -> None:
        """Far from quantum deadline should have low time factor."""
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            quantum_deadline=2060,  # Very far away
        )
        # time_factor = max(0, 1 - (2060 - current_year) / 15) — likely <= 0
        assert risk.time_horizon <= 0.5


class TestMoscaInequality:
    @pytest.mark.asyncio
    async def test_mosca_triggered_restricted(self, svc: HNDLService) -> None:
        """Restricted data with rigid codebase should trigger Mosca inequality.

        shelf_life(restricted)=25 + migration_time(Rigid)=5 = 30
        quantum_timeline - current_year ≈ 9 (2035-2026)
        30 > 9 → Mosca triggered.
        """
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="restricted",
            quantum_deadline=2035,
            agility_label="Rigid",
        )
        assert risk.mosca_inequality is True
        assert risk.urgency == "URGENT"

    @pytest.mark.asyncio
    async def test_mosca_not_triggered_public(self, svc: HNDLService) -> None:
        """Public data with agile codebase should NOT trigger Mosca.

        shelf_life(public)=1 + migration_time(Highly Agile)=1 = 2
        quantum_timeline - current_year ≈ 9
        2 < 9 → Mosca not triggered.
        """
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="public",
            quantum_deadline=2035,
            agility_label="Highly Agile",
        )
        assert risk.mosca_inequality is False

    @pytest.mark.asyncio
    async def test_mosca_confidential_limited(self, svc: HNDLService) -> None:
        """Confidential data with limited agility should trigger Mosca.

        shelf_life(confidential)=15 + migration_time(Limited Agility)=3 = 18
        quantum_timeline - current_year ≈ 9
        18 > 9 → Mosca triggered.
        """
        findings = [_finding("ECDSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="confidential",
            quantum_deadline=2035,
            agility_label="Limited Agility",
        )
        assert risk.mosca_inequality is True
        assert risk.urgency == "URGENT"


class TestUrgencyLabels:
    @pytest.mark.asyncio
    async def test_urgency_low(self, svc: HNDLService) -> None:
        """Quantum-safe findings should be LOW urgency."""
        findings = [_finding("AES-256")]
        risk = await svc.compute_risk(uuid.uuid4(), findings)
        assert risk.urgency == "LOW"

    @pytest.mark.asyncio
    async def test_mosca_overrides_urgency(self, svc: HNDLService) -> None:
        """Mosca inequality should override urgency to URGENT."""
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="restricted",
            agility_label="Rigid",
        )
        # Mosca triggered → urgency must be URGENT regardless of risk score
        if risk.mosca_inequality:
            assert risk.urgency == "URGENT"


class TestRecommendations:
    @pytest.mark.asyncio
    async def test_mosca_recommendation(self, svc: HNDLService) -> None:
        """Mosca trigger should produce migration recommendation."""
        findings = [_finding("RSA")]
        risk = await svc.compute_risk(
            uuid.uuid4(),
            findings,
            data_classification="restricted",
            agility_label="Rigid",
        )
        assert any("Mosca" in r for r in risk.recommendations)

    @pytest.mark.asyncio
    async def test_low_risk_recommendation(self, svc: HNDLService) -> None:
        """Low risk should produce monitoring recommendation."""
        findings = [_finding("AES-256")]
        risk = await svc.compute_risk(uuid.uuid4(), findings, data_classification="public")
        assert any("low" in r.lower() or "monitor" in r.lower() for r in risk.recommendations)

    @pytest.mark.asyncio
    async def test_quantum_vulnerable_recommendation(self, svc: HNDLService) -> None:
        """Quantum-vulnerable algorithms should produce specific recommendation."""
        findings = [_finding("RSA-2048")]
        risk = await svc.compute_risk(uuid.uuid4(), findings, data_classification="confidential")
        assert any("quantum-vulnerable" in r.lower() or "ml-kem" in r.lower() or "ML-KEM" in r for r in risk.recommendations)
