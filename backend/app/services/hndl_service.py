"""HNDL (Harvest Now Decrypt Later) risk model service (ADR-032).

Computes per-project risk using: risk = data_sensitivity x quantum_vulnerability x time_factor.
Includes Mosca inequality urgency flag.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from app.schemas.hndl import HNDLRisk
from app.services.compliance_service import (
    QUANTUM_SAFE_FAMILIES,
    QUANTUM_VULNERABLE_FAMILIES,
    _extract_algorithm_family,
)

logger = logging.getLogger(__name__)

# Data sensitivity classification values (ADR-032)
_SENSITIVITY_MAP: dict[str, float] = {
    "public": 0.1,
    "internal": 0.4,
    "confidential": 0.7,
    "restricted": 1.0,
}

# Quantum vulnerability values (ADR-032)
_QUANTUM_VULNERABILITY: dict[str, float] = {
    "quantum-safe": 0.0,
    "hybrid": 0.2,
    "unknown": 0.5,
    "quantum-vulnerable": 1.0,
}

# Shelf life by data classification (years) for Mosca inequality
_SHELF_LIFE: dict[str, int] = {
    "public": 1,
    "internal": 5,
    "confidential": 15,
    "restricted": 25,
}

# Migration time by agility label (years) for Mosca inequality
_MIGRATION_TIME: dict[str, int] = {
    "Highly Agile": 1,
    "Moderately Agile": 2,
    "Limited Agility": 3,
    "Rigid": 5,
}

# Default quantum deadline (configurable via CRADAR_QUANTUM_DEADLINE)
_DEFAULT_QUANTUM_DEADLINE = 2035
_PLANNING_HORIZON = 15

# Hybrid algorithm families
_HYBRID_FAMILIES: set[str] = {
    "x25519-ml-kem",
    "rsa-ml-kem",
}


def _classify_quantum_vulnerability(algorithm_family: str) -> str:
    """Classify an algorithm's quantum vulnerability status."""
    if algorithm_family in QUANTUM_SAFE_FAMILIES:
        return "quantum-safe"
    if algorithm_family in _HYBRID_FAMILIES:
        return "hybrid"
    if algorithm_family in QUANTUM_VULNERABLE_FAMILIES:
        return "quantum-vulnerable"
    return "unknown"


def _compute_time_factor(
    current_year: int,
    quantum_deadline: int = _DEFAULT_QUANTUM_DEADLINE,
) -> float:
    """Compute time factor: max(0, 1 - (deadline - current_year) / 15)."""
    if current_year >= quantum_deadline:
        return 1.0
    return max(0.0, 1.0 - (quantum_deadline - current_year) / _PLANNING_HORIZON)


def _urgency_label(risk_score: float) -> str:
    """Map risk score 0-1 to urgency label."""
    if risk_score >= 0.80:
        return "URGENT"
    if risk_score >= 0.50:
        return "HIGH"
    if risk_score >= 0.20:
        return "MEDIUM"
    return "LOW"


class HNDLService:
    """Computes Harvest Now Decrypt Later risk scores."""

    async def compute_risk(
        self,
        project_id: Any,
        findings: list[Any],
        data_classification: str = "internal",
        quantum_deadline: int = _DEFAULT_QUANTUM_DEADLINE,
        agility_label: str = "Limited Agility",
    ) -> HNDLRisk:
        """Compute Harvest Now Decrypt Later risk score.

        Formula: risk = data_sensitivity x quantum_vulnerability x time_factor.

        Args:
            project_id: Project UUID (for context).
            findings: List of finding objects.
            data_classification: Data sensitivity classification (public/internal/confidential/restricted).
            quantum_deadline: Expected year of CRQC availability.
            agility_label: Agility score label for Mosca inequality calculation.
        """
        data_sensitivity = _SENSITIVITY_MAP.get(data_classification.lower(), 0.4)
        current_year = datetime.now(tz=timezone.utc).year
        time_factor = _compute_time_factor(current_year, quantum_deadline)

        # Compute aggregate quantum vulnerability across all findings
        if not findings:
            return HNDLRisk(
                risk_score=0.0,
                urgency="LOW",
                data_sensitivity=data_sensitivity,
                quantum_exposure=0.0,
                time_horizon=time_factor,
                mosca_inequality=False,
                recommendations=["No findings to assess"],
            )

        vuln_scores: list[float] = []
        for f in findings:
            algo = _extract_algorithm_family(f)
            status = _classify_quantum_vulnerability(algo)
            vuln_scores.append(_QUANTUM_VULNERABILITY[status])

        # Aggregate: use maximum vulnerability (conservative) for project-level risk
        max_vuln = max(vuln_scores) if vuln_scores else 0.0
        avg_vuln = sum(vuln_scores) / len(vuln_scores) if vuln_scores else 0.0

        # Use weighted combination: 70% max + 30% average
        # This prevents averaging away critical findings (per ADR-032)
        quantum_exposure = 0.7 * max_vuln + 0.3 * avg_vuln

        # Multiplicative risk score
        risk_score = round(data_sensitivity * quantum_exposure * time_factor, 4)
        risk_score = min(1.0, max(0.0, risk_score))

        # Mosca inequality check
        shelf_life = _SHELF_LIFE.get(data_classification.lower(), 5)
        migration_time = _MIGRATION_TIME.get(agility_label, 3)
        years_until_quantum = max(0, quantum_deadline - current_year)
        mosca = (shelf_life + migration_time) > years_until_quantum

        # Urgency: Mosca overrides to URGENT if the inequality holds
        urgency = _urgency_label(risk_score)
        if mosca and urgency != "URGENT":
            urgency = "URGENT"

        # Generate recommendations
        recommendations = self._build_recommendations(
            risk_score=risk_score,
            mosca=mosca,
            data_classification=data_classification,
            quantum_exposure=quantum_exposure,
            max_vuln=max_vuln,
            years_until_quantum=years_until_quantum,
        )

        return HNDLRisk(
            risk_score=risk_score,
            urgency=urgency,
            data_sensitivity=data_sensitivity,
            quantum_exposure=round(quantum_exposure, 4),
            time_horizon=round(time_factor, 4),
            mosca_inequality=mosca,
            recommendations=recommendations,
        )

    def _build_recommendations(
        self,
        risk_score: float,
        mosca: bool,
        data_classification: str,
        quantum_exposure: float,
        max_vuln: float,
        years_until_quantum: int,
    ) -> list[str]:
        """Build context-specific recommendations based on risk factors."""
        recs: list[str] = []

        if mosca:
            recs.append(
                "Mosca inequality triggered — migration deadline has passed. "
                "Begin PQC migration immediately."
            )

        if max_vuln >= 1.0:
            recs.append(
                "Quantum-vulnerable algorithms detected (RSA, ECDSA, ECDH, DH, DSA). "
                "Prioritise migration to ML-KEM / ML-DSA."
            )

        if data_classification.lower() in ("confidential", "restricted"):
            recs.append(
                f"Data classified as '{data_classification}' — long shelf life increases HNDL risk. "
                "Consider hybrid key exchange (X25519+ML-KEM) as interim measure."
            )

        if risk_score >= 0.50:
            recs.append(
                f"High HNDL risk ({risk_score:.2f}). "
                f"Estimated {years_until_quantum} years until CRQC. "
                "Accelerate PQC migration planning."
            )
        elif risk_score >= 0.20:
            recs.append(
                f"Medium HNDL risk ({risk_score:.2f}). "
                "Plan migration within the next 2 years."
            )

        if not recs:
            recs.append("HNDL risk is low. Continue monitoring.")

        return recs
