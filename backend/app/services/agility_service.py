"""Cryptographic Agility Score service (ADR-031).

Computes a 0-100 composite agility score from 5 weighted factors.
"""

import logging
from typing import Any

from app.schemas.agility import AgilityScore, FactorScore
from app.services.compliance_service import (
    QUANTUM_SAFE_FAMILIES,
    QUANTUM_VULNERABLE_FAMILIES,
    _MIGRATION_TARGETS,
    _extract_algorithm_family,
)

logger = logging.getLogger(__name__)

# Algorithms with known PQC replacements (from _MIGRATION_TARGETS + quantum-safe ones)
_PQC_REPLACEABLE: set[str] = set(_MIGRATION_TARGETS.keys()) | QUANTUM_SAFE_FAMILIES


def _label_for_score(score: float) -> str:
    """Map agility score to display label per ADR-031."""
    if score >= 80:
        return "Highly Agile"
    if score >= 60:
        return "Moderately Agile"
    if score >= 40:
        return "Limited Agility"
    return "Rigid"


class AgilityService:
    """Computes the 5-factor cryptographic agility score."""

    async def compute_score(self, project_id: Any, findings: list[Any]) -> AgilityScore:
        """Compute 0-100 agility score with 5 weighted factors.

        Args:
            project_id: Project UUID (used for context, not computation).
            findings: List of finding objects with name, severity, properties.
        """
        factors: list[FactorScore] = []
        recommendations: list[str] = []

        # ---------------------------------------------------------------
        # Factor 1: Call Site Concentration (20%)
        # ---------------------------------------------------------------
        unique_files: set[str] = set()
        for f in findings:
            location = getattr(f, "location_file", None) or ""
            if location:
                unique_files.add(location)

        file_count = len(unique_files)
        if file_count <= 3:
            f1_score = 100.0
        elif file_count <= 10:
            f1_score = 75.0
        elif file_count <= 25:
            f1_score = 50.0
        elif file_count <= 50:
            f1_score = 25.0
        else:
            f1_score = 0.0

        if f1_score < 75:
            recommendations.append(
                f"Consolidate crypto call sites — currently spread across {file_count} files"
            )

        factors.append(
            FactorScore(
                name="call_site_concentration",
                weight=0.20,
                score=f1_score,
                details=f"{file_count} unique files contain crypto calls",
            )
        )

        # ---------------------------------------------------------------
        # Factor 2: Abstraction Level (25%)
        # ---------------------------------------------------------------
        total_calls = len(findings)
        wrapper_calls = 0
        for f in findings:
            props = getattr(f, "properties", None) or {}
            # A finding is considered wrapped if it has a wrapper function
            # or if its call depth > 1 (intermediary function)
            if props.get("is_wrapper") or props.get("call_depth", 0) > 1:
                wrapper_calls += 1

        if total_calls == 0:
            f2_score = 100.0
        else:
            wrapper_pct = wrapper_calls / total_calls
            if wrapper_pct >= 1.0:
                f2_score = 100.0
            elif wrapper_pct >= 0.70:
                f2_score = 75.0
            elif wrapper_pct >= 0.30:
                f2_score = 50.0
            elif wrapper_pct > 0:
                f2_score = 25.0
            else:
                f2_score = 0.0

        if f2_score < 75:
            recommendations.append(
                "Introduce crypto abstraction wrappers to decouple algorithm choice from call sites"
            )

        factors.append(
            FactorScore(
                name="abstraction_level",
                weight=0.25,
                score=f2_score,
                details=f"{wrapper_calls}/{total_calls} calls use wrapper functions",
            )
        )

        # ---------------------------------------------------------------
        # Factor 3: Algorithm Diversity (15%)
        # ---------------------------------------------------------------
        unique_algorithms: set[str] = set()
        for f in findings:
            algo = _extract_algorithm_family(f)
            if algo != "unknown":
                unique_algorithms.add(algo)

        algo_count = len(unique_algorithms)
        if algo_count <= 2:
            f3_score = 100.0
        elif algo_count <= 5:
            f3_score = 75.0
        elif algo_count <= 10:
            f3_score = 50.0
        elif algo_count <= 20:
            f3_score = 25.0
        else:
            f3_score = 0.0

        if f3_score < 75:
            recommendations.append(
                f"Reduce algorithm diversity — {algo_count} unique algorithms in use"
            )

        factors.append(
            FactorScore(
                name="algorithm_diversity",
                weight=0.15,
                score=f3_score,
                details=f"{algo_count} unique algorithms detected",
            )
        )

        # ---------------------------------------------------------------
        # Factor 4: Key Management Centralisation (20%)
        # ---------------------------------------------------------------
        kms_count = 0
        hardcoded_count = 0
        config_count = 0
        for f in findings:
            props = getattr(f, "properties", None) or {}
            key_mgmt = props.get("key_management", "").lower()
            if key_mgmt in ("kms", "hsm", "vault"):
                kms_count += 1
            elif key_mgmt in ("hardcoded", "embedded"):
                hardcoded_count += 1
            elif key_mgmt in ("config", "environment", "env"):
                config_count += 1

        key_total = kms_count + hardcoded_count + config_count
        if key_total == 0:
            # No key management info available — assume config-based (50)
            f4_score = 50.0
        else:
            kms_pct = kms_count / key_total
            hardcoded_pct = hardcoded_count / key_total
            if kms_pct >= 1.0:
                f4_score = 100.0
            elif kms_pct >= 0.50:
                f4_score = 75.0
            elif hardcoded_pct == 0:
                f4_score = 50.0
            elif hardcoded_pct < 0.50:
                f4_score = 25.0
            else:
                f4_score = 0.0

        if hardcoded_count > 0:
            recommendations.append(
                f"Migrate {hardcoded_count} hardcoded key(s) to a centralised KMS/vault"
            )

        factors.append(
            FactorScore(
                name="key_management",
                weight=0.20,
                score=f4_score,
                details=f"KMS: {kms_count}, config: {config_count}, hardcoded: {hardcoded_count}",
            )
        )

        # ---------------------------------------------------------------
        # Factor 5: Migration Readiness (20%)
        # ---------------------------------------------------------------
        replaceable = 0
        total_classified = 0
        for f in findings:
            algo = _extract_algorithm_family(f)
            if algo == "unknown":
                continue
            total_classified += 1
            if algo in _PQC_REPLACEABLE:
                replaceable += 1

        if total_classified == 0:
            f5_score = 100.0
        else:
            pct = replaceable / total_classified
            if pct >= 1.0:
                f5_score = 100.0
            elif pct >= 0.75:
                f5_score = 75.0
            elif pct >= 0.50:
                f5_score = 50.0
            elif pct >= 0.25:
                f5_score = 25.0
            else:
                f5_score = 0.0

        if f5_score < 75:
            recommendations.append(
                "Investigate PQC migration paths for algorithms without known replacements"
            )

        factors.append(
            FactorScore(
                name="migration_readiness",
                weight=0.20,
                score=f5_score,
                details=f"{replaceable}/{total_classified} algorithms have known PQC replacement",
            )
        )

        # ---------------------------------------------------------------
        # Composite score
        # ---------------------------------------------------------------
        total_score = sum(f.weight * f.score for f in factors)
        total_score = round(total_score, 1)
        label = _label_for_score(total_score)

        return AgilityScore(
            total_score=total_score,
            label=label,
            factors=factors,
            recommendations=recommendations,
        )
