"""Compliance engine — evaluates cryptographic findings against frameworks.

Loads algorithm classification data from scanner/library-models/ YAML files
at module import time using importlib.resources (embedded, never fetched at runtime).
"""

import importlib.resources
import logging
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from app.schemas.compliance import (
    ComplianceItem,
    ComplianceReport,
    EvidenceItem,
    EvidenceReport,
    GapItem,
    GapReport,
    MigrationItem,
    QuantumRiskScore,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# YAML data loading — embedded at startup via importlib.resources
# ---------------------------------------------------------------------------

_SCANNER_PKG = "scanner"


def _locate_library_models_dir() -> Path:
    """Locate the scanner/library-models/ directory.

    Tries importlib.resources first (works when scanner is an installed package),
    then falls back to path traversal from the repo root (development mode).
    """
    # Attempt 1: importlib.resources (installed package)
    try:
        ref = importlib.resources.files(_SCANNER_PKG)
        models_dir = Path(str(ref)) / "library-models"
        if models_dir.is_dir():
            return models_dir
    except (ModuleNotFoundError, TypeError):
        pass

    # Attempt 2: path relative to repo root (development)
    # backend/ is one level below the repo root
    backend_dir = Path(__file__).resolve().parent.parent.parent  # app/services/ -> app/ -> backend/
    repo_root = backend_dir.parent  # backend/ -> repo root
    models_dir = repo_root / "scanner" / "library-models"
    if models_dir.is_dir():
        return models_dir

    msg = (
        "Cannot locate scanner/library-models/ directory. "
        "Ensure the scanner package is installed or the repo structure is intact."
    )
    raise FileNotFoundError(msg)


def _load_yaml(filename: str) -> dict[str, Any]:
    """Load a YAML file from the library-models directory."""
    models_dir = _locate_library_models_dir()
    filepath = models_dir / filename
    with open(filepath) as f:
        return yaml.safe_load(f)


# Load framework data at module import time
_nist_data: dict[str, Any] = _load_yaml("nist_800_131a.yml")
_fips_data: dict[str, Any] = _load_yaml("fips_140_3.yml")
_pci_dss_data: dict[str, Any] = _load_yaml("pci_dss_v4.yml")
_cnsa2_data: dict[str, Any] = _load_yaml("cnsa_2.yml")
_iso27001_data: dict[str, Any] = _load_yaml("iso_27001_a8_24.yml")
_eu_cra_data: dict[str, Any] = _load_yaml("eu_cra.yml")

# Build lookup tables for fast classification
# Key: algorithm family (lowercase), Value: list of rule dicts
_nist_rules: list[dict[str, Any]] = _nist_data.get("algorithms", [])
_fips_rules: list[dict[str, Any]] = _fips_data.get("algorithms", [])
_pci_dss_rules: list[dict[str, Any]] = _pci_dss_data.get("algorithms", [])
_cnsa2_rules: list[dict[str, Any]] = _cnsa2_data.get("algorithms", [])
_iso27001_checklist: list[dict[str, Any]] = _iso27001_data.get("checklist", [])
_eu_cra_requirements: list[dict[str, Any]] = _eu_cra_data.get("essential_requirements", [])

# ---------------------------------------------------------------------------
# Quantum vulnerability classification
# ---------------------------------------------------------------------------

# Algorithms that are quantum-vulnerable (can be broken by quantum computers)
QUANTUM_VULNERABLE_FAMILIES: set[str] = {
    "rsa",
    "ecdsa",
    "ecdh",
    "ecc",
    "dh",
    "dsa",
}

# Algorithms that are already broken (classically, not just quantum)
BROKEN_FAMILIES: set[str] = {
    "des",
    "3des",
    "rc4",
    "md5",
    "md4",
}

# Quantum-safe algorithm families
QUANTUM_SAFE_FAMILIES: set[str] = {
    "aes",
    "sha256",
    "sha384",
    "sha512",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
}

# Severity weights for quantum risk scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}

# Default PQC migration targets
_MIGRATION_TARGETS: dict[str, str] = {
    "rsa": "ml-dsa",
    "ecdsa": "ml-dsa",
    "ecdh": "ml-kem",
    "ecc": "ml-kem",
    "dh": "ml-kem",
    "dsa": "ml-dsa",
}


def _extract_algorithm_family(finding: Any) -> str:
    """Extract a normalised algorithm family name from a finding.

    Looks at the finding name (lowercased) and matches against known families.
    Also checks finding.properties for an explicit 'algorithm_family' key.
    """
    # Check explicit property first
    props = getattr(finding, "properties", None) or {}
    if explicit := props.get("algorithm_family"):
        return str(explicit).lower().strip()

    name_lower = getattr(finding, "name", "").lower()

    # Order matters: check specific families before generic ones
    family_keywords = [
        ("sha3-512", "sha3-512"),
        ("sha3-384", "sha3-384"),
        ("sha3-256", "sha3-256"),
        ("sha-3", "sha3-256"),  # generic SHA-3 reference
        ("sha3", "sha3-256"),
        ("sha-512", "sha512"),
        ("sha512", "sha512"),
        ("sha-384", "sha384"),
        ("sha384", "sha384"),
        ("sha-256", "sha256"),
        ("sha256", "sha256"),
        ("sha-1", "sha1"),
        ("sha1", "sha1"),
        ("md5", "md5"),
        ("md4", "md4"),
        ("3des", "3des"),
        ("triple-des", "3des"),
        ("triple des", "3des"),
        ("tripledes", "3des"),
        ("des-ede", "3des"),
        ("des", "des"),
        ("rc4", "rc4"),
        ("aes", "aes"),
        ("blowfish", "blowfish"),
        ("chacha20", "chacha20"),
        ("ml-kem", "ml-kem"),
        ("kyber", "ml-kem"),
        ("ml-dsa", "ml-dsa"),
        ("dilithium", "ml-dsa"),
        ("slh-dsa", "slh-dsa"),
        ("sphincs", "slh-dsa"),
        ("ecdsa", "ecdsa"),
        ("ecdh", "ecdh"),
        ("ecc", "ecc"),
        ("rsa", "rsa"),
        ("dsa", "dsa"),
        ("diffie-hellman", "dh"),
        ("dh", "dh"),
        ("hmac-drbg", "hmac-drbg"),
        ("hash-drbg", "hash-drbg"),
        ("ctr-drbg", "ctr-drbg"),
        ("math.random", "math-random"),
        ("math_random", "math-random"),
        ("rand()", "rand"),
    ]

    for keyword, family in family_keywords:
        if keyword in name_lower:
            return family

    return "unknown"


def _get_key_size(finding: Any) -> int | None:
    """Extract key size from finding properties if available."""
    props = getattr(finding, "properties", None) or {}
    key_size = props.get("key_size") or props.get("keySize")
    if key_size is not None:
        try:
            return int(key_size)
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# NIST SP 800-131A evaluation
# ---------------------------------------------------------------------------


def _classify_nist(family: str, key_size: int | None) -> dict[str, Any]:
    """Classify an algorithm family under NIST SP 800-131A.

    Returns the matching rule dict, or a default 'unknown' classification.
    """
    matching_rules = [r for r in _nist_rules if r["family"] == family]

    if not matching_rules:
        return {"family": family, "classification": "unknown", "note": "Not classified in NIST SP 800-131A"}

    # If there are key-size-dependent rules, pick the right one
    if len(matching_rules) > 1 and key_size is not None:
        for rule in matching_rules:
            min_ks = rule.get("min_key_size")
            max_ks = rule.get("max_key_size")
            if max_ks is not None and key_size <= max_ks:
                return rule
            if min_ks is not None and key_size >= min_ks:
                return rule

    # If only one rule or no key size info, pick the first non-disallowed
    # (prefer the more specific classification)
    if key_size is not None:
        for rule in matching_rules:
            min_ks = rule.get("min_key_size")
            if min_ks is not None and key_size < min_ks:
                # Below minimum → disallowed
                return {
                    "family": family,
                    "classification": "disallowed",
                    "note": f"Key size {key_size} below minimum {min_ks}",
                }

    # Default: return the first matching rule
    return matching_rules[0]


def _action_for_nist(classification: str) -> str:
    """Map NIST classification to action required."""
    if classification == "disallowed":
        return "immediate-remediation"
    if classification == "deprecated":
        return "schedule-migration"
    return "none"


class ComplianceService:
    """Evaluates cryptographic findings against compliance frameworks."""

    async def evaluate_nist_800_131a(self, findings: list[Any]) -> ComplianceReport:
        """Evaluate findings against NIST SP 800-131A Rev. 3.

        Each finding is classified as acceptable, deprecated, or disallowed.
        The score is 100 minus weighted penalties for non-compliant findings.
        """
        if not findings:
            return ComplianceReport(
                framework="nist-800-131a",
                score=100.0,
                total_findings=0,
                compliant_count=0,
                non_compliant_count=0,
                items=[],
            )

        # Group findings by algorithm family
        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        items: list[ComplianceItem] = []
        compliant = 0
        non_compliant = 0
        total_penalty = 0.0
        total = len(findings)

        for family, count in sorted(family_counter.items()):
            key_size = family_key_sizes.get(family)
            rule = _classify_nist(family, key_size)
            classification = rule.get("classification", "unknown")
            note = rule.get("note", "")

            action = _action_for_nist(classification)

            if classification == "acceptable":
                compliant += count
            elif classification in ("deprecated", "disallowed", "unknown"):
                non_compliant += count
                # Penalty: disallowed = 3 points per finding, deprecated = 1 point
                if classification == "disallowed":
                    total_penalty += count * 3.0
                elif classification == "deprecated":
                    total_penalty += count * 1.0
                else:
                    total_penalty += count * 0.5  # unknown

            items.append(
                ComplianceItem(
                    algorithm=family,
                    classification=classification,
                    count=count,
                    note=note,
                    action_required=action,
                )
            )

        # Score: start at 100, subtract penalty normalized to total findings
        # Max possible penalty = total * 3 (all disallowed)
        max_penalty = total * 3.0
        score = max(0.0, 100.0 * (1.0 - total_penalty / max_penalty)) if max_penalty > 0 else 100.0
        score = round(score, 1)

        return ComplianceReport(
            framework="nist-800-131a",
            score=score,
            total_findings=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            items=items,
        )

    async def evaluate_fips_140_3(self, findings: list[Any]) -> ComplianceReport:
        """Evaluate findings against FIPS 140-3 approved algorithm list.

        Each finding is classified as approved or not-approved.
        """
        if not findings:
            return ComplianceReport(
                framework="fips-140-3",
                score=100.0,
                total_findings=0,
                compliant_count=0,
                non_compliant_count=0,
                items=[],
            )

        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        items: list[ComplianceItem] = []
        compliant = 0
        non_compliant = 0
        total = len(findings)

        for family, count in sorted(family_counter.items()):
            key_size = family_key_sizes.get(family)
            rule = self._classify_fips(family, key_size)
            classification = rule.get("classification", "unknown")
            note = rule.get("note", "")

            if classification == "approved":
                compliant += count
                action = "none"
            else:
                non_compliant += count
                action = "immediate-remediation"

            items.append(
                ComplianceItem(
                    algorithm=family,
                    classification=classification,
                    count=count,
                    note=note,
                    action_required=action,
                )
            )

        # Score: percentage of compliant findings
        score = round(100.0 * compliant / total, 1) if total > 0 else 100.0

        return ComplianceReport(
            framework="fips-140-3",
            score=score,
            total_findings=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            items=items,
        )

    def _classify_fips(self, family: str, key_size: int | None) -> dict[str, Any]:
        """Classify an algorithm family under FIPS 140-3."""
        matching_rules = [r for r in _fips_rules if r["family"] == family]

        if not matching_rules:
            return {"family": family, "classification": "not-approved", "note": "Not listed in FIPS 140-3"}

        rule = matching_rules[0]

        # Check key size requirements
        min_ks = rule.get("min_key_size")
        if min_ks is not None and key_size is not None and key_size < min_ks:
            return {
                "family": family,
                "classification": "not-approved",
                "note": f"Key size {key_size} below FIPS minimum {min_ks}",
            }

        return rule

    async def compute_quantum_risk_score(self, findings: list[Any]) -> QuantumRiskScore:
        """Compute a quantum risk score from 0 (fully safe) to 100 (critically exposed).

        Formula: each quantum-vulnerable algorithm contributes
          count * severity_weight * exposure_factor
        Broken algorithms count double.
        Score is normalized to 0-100.
        """
        if not findings:
            return QuantumRiskScore(
                score=0.0,
                vulnerable_count=0,
                safe_count=0,
                broken_count=0,
                migration_items=[],
            )

        vulnerable_count = 0
        safe_count = 0
        broken_count = 0
        raw_risk = 0.0
        max_possible_risk = 0.0

        # Group by family for migration items
        vuln_families: Counter[str] = Counter()
        family_severities: dict[str, str] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            severity = getattr(f, "severity", "medium").lower()
            weight = _SEVERITY_WEIGHTS.get(severity, 4.0)

            # Maximum possible contribution per finding (critical + broken = 10 * 2 = 20)
            max_possible_risk += 10.0 * 2.0

            if family in BROKEN_FAMILIES:
                broken_count += 1
                vulnerable_count += 1
                raw_risk += weight * 2.0  # broken algorithms count double
                vuln_families[family] += 1
                if family not in family_severities or severity == "critical":
                    family_severities[family] = severity
            elif family in QUANTUM_VULNERABLE_FAMILIES:
                vulnerable_count += 1
                raw_risk += weight * 1.0
                vuln_families[family] += 1
                if family not in family_severities or severity == "critical":
                    family_severities[family] = severity
            elif family in QUANTUM_SAFE_FAMILIES:
                safe_count += 1
            else:
                # Unknown algorithms treated as potentially vulnerable
                vulnerable_count += 1
                raw_risk += weight * 0.5
                vuln_families[family] += 1
                if family not in family_severities:
                    family_severities[family] = severity

        # Normalize to 0-100
        score = round(100.0 * raw_risk / max_possible_risk, 1) if max_possible_risk > 0 else 0.0
        score = min(100.0, score)

        # Build migration items sorted by priority (highest risk first)
        migration_items: list[MigrationItem] = []
        priority = 1
        for family, count in vuln_families.most_common():
            sev = family_severities.get(family, "medium")
            migrate_to = _MIGRATION_TARGETS.get(family, "")

            # Broken families: severity is always critical for migration purposes
            if family in BROKEN_FAMILIES:
                sev = "critical"

            migration_items.append(
                MigrationItem(
                    algorithm=family,
                    count=count,
                    severity=sev,
                    migrate_to=migrate_to,
                    priority=priority,
                )
            )
            priority += 1

        return QuantumRiskScore(
            score=score,
            vulnerable_count=vulnerable_count,
            safe_count=safe_count,
            broken_count=broken_count,
            migration_items=migration_items,
        )

    async def get_migration_priority_queue(self, findings: list[Any]) -> list[MigrationItem]:
        """Return a prioritized list of algorithms that need migration.

        Sorted by: broken first, then by count * severity descending.
        """
        qrs = await self.compute_quantum_risk_score(findings)
        return qrs.migration_items

    # ---------------------------------------------------------------------------
    # PCI-DSS v4.0 evaluation
    # ---------------------------------------------------------------------------

    async def evaluate_pci_dss_v4(self, findings: list[Any]) -> ComplianceReport:
        """Evaluate findings against PCI-DSS v4.0 cryptographic requirements.

        Requirements checked: 2.2.7 (strong crypto), 3.5 (key mgmt),
        4.2 (data in transit), 6.2.4 (secure coding).
        Score: 100 minus weighted penalties for non-compliant findings.
        """
        if not findings:
            return ComplianceReport(
                framework="pci-dss-v4",
                score=100.0,
                total_findings=0,
                compliant_count=0,
                non_compliant_count=0,
                items=[],
            )

        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        items: list[ComplianceItem] = []
        compliant = 0
        non_compliant = 0
        total = len(findings)

        for family, count in sorted(family_counter.items()):
            key_size = family_key_sizes.get(family)
            rule = self._classify_pci_dss(family, key_size)
            classification = rule.get("classification", "unknown")
            note = rule.get("note", "")
            requirement = rule.get("requirement", "")
            if requirement:
                note = f"[Req {requirement}] {note}" if note else f"[Req {requirement}]"

            if classification == "compliant":
                compliant += count
                action = "none"
            else:
                non_compliant += count
                action = "immediate-remediation"

            items.append(
                ComplianceItem(
                    algorithm=family,
                    classification=classification,
                    count=count,
                    note=note,
                    action_required=action,
                )
            )

        score = round(100.0 * compliant / total, 1) if total > 0 else 100.0

        return ComplianceReport(
            framework="pci-dss-v4",
            score=score,
            total_findings=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            items=items,
        )

    def _classify_pci_dss(self, family: str, key_size: int | None) -> dict[str, Any]:
        """Classify an algorithm family under PCI-DSS v4.0."""
        matching_rules = [r for r in _pci_dss_rules if r["family"] == family]

        if not matching_rules:
            return {
                "family": family,
                "classification": "unknown",
                "note": "Not classified in PCI-DSS v4.0",
            }

        rule = matching_rules[0]

        # Check key size requirements
        min_ks = rule.get("min_key_size")
        if min_ks is not None and key_size is not None and key_size < min_ks:
            return {
                "family": family,
                "classification": "non-compliant",
                "note": f"Key size {key_size} below PCI-DSS minimum {min_ks}",
                "requirement": rule.get("requirement", ""),
            }

        return rule

    # ---------------------------------------------------------------------------
    # CNSA 2.0 evaluation
    # ---------------------------------------------------------------------------

    async def evaluate_cnsa_2(self, findings: list[Any]) -> ComplianceReport:
        """Evaluate findings against NSA CNSA 2.0 algorithm suite.

        Score: percentage of approved findings.
        Migration deadlines are included per non-approved algorithm.
        """
        if not findings:
            return ComplianceReport(
                framework="cnsa-2",
                score=100.0,
                total_findings=0,
                compliant_count=0,
                non_compliant_count=0,
                items=[],
                migration_deadlines={},
            )

        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        items: list[ComplianceItem] = []
        compliant = 0
        non_compliant = 0
        total = len(findings)
        migration_deadlines: dict[str, str] = {}

        for family, count in sorted(family_counter.items()):
            key_size = family_key_sizes.get(family)
            rule = self._classify_cnsa2(family, key_size)
            classification = rule.get("classification", "unknown")
            note = rule.get("note", "")

            deadline = rule.get("deadline")
            software_deadline = rule.get("software_deadline")
            migrate_to = rule.get("migrate_to", "")

            if classification == "approved":
                compliant += count
                action = "none"
            elif classification == "deprecated":
                non_compliant += count
                action = "schedule-migration"
                dl = software_deadline or deadline or "2030"
                migration_deadlines[family] = dl
                if migrate_to:
                    note = f"{note} → migrate to {migrate_to} by {dl}"
            else:
                non_compliant += count
                action = "immediate-remediation"
                if deadline:
                    migration_deadlines[family] = str(deadline)

            items.append(
                ComplianceItem(
                    algorithm=family,
                    classification=classification,
                    count=count,
                    note=note,
                    action_required=action,
                )
            )

        score = round(100.0 * compliant / total, 1) if total > 0 else 100.0

        return ComplianceReport(
            framework="cnsa-2",
            score=score,
            total_findings=total,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            items=items,
            migration_deadlines=migration_deadlines,
        )

    def _classify_cnsa2(self, family: str, key_size: int | None) -> dict[str, Any]:
        """Classify an algorithm family under CNSA 2.0."""
        matching_rules = [r for r in _cnsa2_rules if r["family"] == family]

        if not matching_rules:
            return {
                "family": family,
                "classification": "not-approved",
                "note": "Not classified in CNSA 2.0",
            }

        rule = matching_rules[0]

        # Check key size (e.g. AES must be 256)
        min_ks = rule.get("min_key_size")
        if min_ks is not None and key_size is not None and key_size < min_ks:
            return {
                "family": family,
                "classification": "not-approved",
                "note": f"Key size {key_size} below CNSA 2.0 minimum {min_ks}",
            }

        return rule

    # ---------------------------------------------------------------------------
    # ISO 27001 A.8.24 evaluation
    # ---------------------------------------------------------------------------

    async def evaluate_iso_27001_a8_24(self, findings: list[Any]) -> EvidenceReport:
        """Evaluate findings against ISO 27001 A.8.24 evidence checklist.

        Returns an evidence report with pass/fail/manual-review per checklist item.
        This is NOT a numeric score — it produces a checklist.
        """
        # Pre-process findings
        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        evidence_items: list[EvidenceItem] = []
        passed = 0
        failed = 0
        manual_review = 0

        for check in _iso27001_checklist:
            check_id = check["id"]
            title = check["title"]
            description = check["description"]
            auto_check = check.get("auto_check", False)

            if not auto_check:
                # Manual review required
                evidence_items.append(
                    EvidenceItem(
                        check_id=check_id,
                        title=title,
                        description=description,
                        status="manual-review",
                        evidence=[check.get("note", "Requires manual verification")],
                        findings_count=0,
                    )
                )
                manual_review += 1
                continue

            # Auto-checkable items
            status, evidence, count = self._evaluate_iso_check(check, family_counter, family_key_sizes)
            evidence_items.append(
                EvidenceItem(
                    check_id=check_id,
                    title=title,
                    description=description,
                    status=status,
                    evidence=evidence,
                    findings_count=count,
                )
            )
            if status == "pass":
                passed += 1
            elif status == "fail":
                failed += 1
            else:
                manual_review += 1

        return EvidenceReport(
            framework="iso-27001-a8-24",
            total_checks=len(evidence_items),
            passed=passed,
            failed=failed,
            manual_review=manual_review,
            items=evidence_items,
        )

    def _evaluate_iso_check(
        self,
        check: dict[str, Any],
        family_counter: Counter[str],
        family_key_sizes: dict[str, int | None],
    ) -> tuple[str, list[str], int]:
        """Evaluate a single ISO 27001 auto-check item.

        Returns (status, evidence_list, findings_count).
        """
        check_id = check["id"]
        evidence: list[str] = []
        count = 0

        if check_id == "A.8.24-3":
            # No broken algorithms
            broken_families = check.get("broken_families", [])
            found_broken: list[str] = []
            for bf in broken_families:
                if bf in family_counter:
                    found_broken.append(bf)
                    count += family_counter[bf]
            if found_broken:
                evidence.append(f"Broken algorithms detected: {', '.join(found_broken)}")
                return "fail", evidence, count
            evidence.append("No broken algorithms detected in codebase")
            return "pass", evidence, 0

        if check_id == "A.8.24-4":
            # Adequate key sizes
            min_key_sizes = check.get("min_key_sizes", {})
            inadequate: list[str] = []
            for algo, min_size in min_key_sizes.items():
                if algo in family_counter:
                    actual_size = family_key_sizes.get(algo)
                    count += family_counter[algo]
                    if actual_size is not None and actual_size < min_size:
                        inadequate.append(f"{algo}: {actual_size} < {min_size}")
            if inadequate:
                evidence.append(f"Inadequate key sizes: {'; '.join(inadequate)}")
                return "fail", evidence, count
            evidence.append("All detected key sizes meet minimum requirements")
            return "pass", evidence, count

        if check_id == "A.8.24-6":
            # Secure RNG
            insecure_families = check.get("insecure_rng_families", [])
            found_insecure: list[str] = []
            for rf in insecure_families:
                if rf in family_counter:
                    found_insecure.append(rf)
                    count += family_counter[rf]
            if found_insecure:
                evidence.append(f"Insecure RNG detected: {', '.join(found_insecure)}")
                return "fail", evidence, count
            evidence.append("No insecure random number generators detected")
            return "pass", evidence, 0

        if check_id == "A.8.24-7":
            # Quantum readiness
            vulnerable_families = check.get("quantum_vulnerable_families", [])
            found_vuln: list[str] = []
            for vf in vulnerable_families:
                if vf in family_counter:
                    found_vuln.append(vf)
                    count += family_counter[vf]
            if found_vuln:
                evidence.append(
                    f"Quantum-vulnerable algorithms in use: {', '.join(found_vuln)}. Migration plan to PQC recommended."
                )
                return "fail", evidence, count
            evidence.append("No quantum-vulnerable algorithms detected")
            return "pass", evidence, 0

        # Fallback for unknown auto-check items
        return "manual-review", ["Auto-check not implemented for this item"], 0

    # ---------------------------------------------------------------------------
    # EU CRA gap analysis
    # ---------------------------------------------------------------------------

    async def evaluate_eu_cra(self, findings: list[Any]) -> GapReport:
        """Evaluate findings against EU CRA Annex I essential requirements.

        Returns a gap report identifying which requirements have gaps.
        This is NOT a numeric score.
        """
        # Pre-process findings
        family_counter: Counter[str] = Counter()
        family_key_sizes: dict[str, int | None] = {}

        for f in findings:
            family = _extract_algorithm_family(f)
            family_counter[family] += 1
            if family not in family_key_sizes:
                family_key_sizes[family] = _get_key_size(f)

        gap_items: list[GapItem] = []
        gaps_found = 0
        no_gaps = 0
        manual_review_count = 0

        for req in _eu_cra_requirements:
            req_id = req["id"]
            title = req["title"]
            description = req.get("description", "")
            auto_check = req.get("auto_check", False)

            if not auto_check:
                gap_items.append(
                    GapItem(
                        requirement_id=req_id,
                        title=title,
                        description=description,
                        gap_status="manual-review",
                        recommendation="Manual review required",
                    )
                )
                manual_review_count += 1
                continue

            # Auto-check: look for non-compliant algorithms in findings
            gap_status, affected_algos, affected_count, recommendation = self._evaluate_cra_requirement(
                req, family_counter, family_key_sizes
            )

            gap_items.append(
                GapItem(
                    requirement_id=req_id,
                    title=title,
                    description=description,
                    gap_status=gap_status,
                    affected_algorithms=affected_algos,
                    affected_count=affected_count,
                    recommendation=recommendation,
                )
            )

            if gap_status == "gap":
                gaps_found += 1
            elif gap_status == "no-gap":
                no_gaps += 1
            else:
                manual_review_count += 1

        return GapReport(
            framework="eu-cra",
            total_requirements=len(gap_items),
            gaps_found=gaps_found,
            no_gaps=no_gaps,
            manual_review=manual_review_count,
            items=gap_items,
        )

    def _evaluate_cra_requirement(
        self,
        req: dict[str, Any],
        family_counter: Counter[str],
        family_key_sizes: dict[str, int | None],
    ) -> tuple[str, list[str], int, str]:
        """Evaluate a single CRA requirement.

        Returns (gap_status, affected_algorithms, affected_count, recommendation).
        """
        check_type = req.get("check_type", "")
        affected: list[str] = []
        total_count = 0

        if check_type in ("algorithm_strength", "broken_algorithms"):
            check_families = req.get("disallowed_families", []) or req.get("broken_families", [])
            for fam in check_families:
                if fam in family_counter:
                    affected.append(fam)
                    total_count += family_counter[fam]
            if affected:
                return (
                    "gap",
                    affected,
                    total_count,
                    f"Replace {', '.join(affected)} with state-of-the-art algorithms",
                )
            return "no-gap", [], 0, ""

        if check_type == "encryption_strength":
            disallowed = req.get("disallowed_encryption", [])
            for entry in disallowed:
                fam = entry.get("family", entry) if isinstance(entry, dict) else entry
                if fam in family_counter:
                    affected.append(fam)
                    total_count += family_counter[fam]
            # Also check approved encryption key sizes
            approved = req.get("approved_encryption", [])
            for entry in approved:
                if isinstance(entry, dict):
                    fam = entry["family"]
                    min_ks = entry.get("min_key_size")
                    if fam in family_counter and min_ks is not None:
                        actual_ks = family_key_sizes.get(fam)
                        if actual_ks is not None and actual_ks < min_ks:
                            affected.append(fam)
                            total_count += family_counter[fam]
            if affected:
                return (
                    "gap",
                    affected,
                    total_count,
                    f"Replace {', '.join(affected)} with approved encryption (AES-128+, ChaCha20)",
                )
            return "no-gap", [], 0, ""

        if check_type == "hash_strength":
            disallowed = req.get("disallowed_hashes", [])
            for fam in disallowed:
                if fam in family_counter:
                    affected.append(fam)
                    total_count += family_counter[fam]
            if affected:
                return (
                    "gap",
                    affected,
                    total_count,
                    f"Replace {', '.join(affected)} with SHA-256+ or SHA-3",
                )
            return "no-gap", [], 0, ""

        if check_type == "auth_crypto":
            # Check that authentication uses approved algorithms with adequate key sizes
            min_key_sizes_map = req.get("min_key_sizes", {})
            # For auth_crypto, a gap exists if we find signature algorithms with
            # inadequate key sizes
            for fam, min_ks in min_key_sizes_map.items():
                if fam in family_counter:
                    actual_ks = family_key_sizes.get(fam)
                    if actual_ks is not None and actual_ks < min_ks:
                        affected.append(fam)
                        total_count += family_counter[fam]
            if affected:
                return (
                    "gap",
                    affected,
                    total_count,
                    "Increase key sizes for authentication algorithms",
                )
            return "no-gap", [], 0, ""

        if check_type == "cbom_completeness":
            # Pass if we have any findings (CBOM exists), otherwise manual review
            if family_counter:
                return "no-gap", [], 0, ""
            return "manual-review", [], 0, "Verify CBOM completeness manually"

        return "manual-review", [], 0, "Manual review required"
