"""Tests for PQCMigrationService — post-quantum migration progress tracking."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.pqc_migration_service import PQCMigrationService


def _finding(
    *,
    quantum_status: str = "vulnerable",
    algorithm_family: str = "RSA",
    project_name: str = "auth-service",
    project_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    """Create a minimal finding for testing."""
    pid = project_id or uuid.uuid4()
    return SimpleNamespace(
        id=uuid.uuid4(),
        quantum_status=quantum_status,
        asset_type="algorithm",
        org_id=uuid.uuid4(),
        project_id=pid,
        properties={"algorithm_family": algorithm_family},
        project=SimpleNamespace(name=project_name, id=pid),
    )


@pytest.fixture
def svc() -> PQCMigrationService:
    return PQCMigrationService()


class TestPercentageCalculation:
    def test_percentage_with_mixed_statuses(self, svc: PQCMigrationService) -> None:
        """Should compute correct percentages for vulnerable/safe/unknown."""
        findings = [
            _finding(quantum_status="vulnerable"),
            _finding(quantum_status="vulnerable"),
            _finding(quantum_status="safe"),
            _finding(quantum_status="unknown"),
        ]
        overview = svc.compute_overview(findings)
        assert overview["total_findings"] == 4
        assert overview["vulnerable"] == 2
        assert overview["safe"] == 1
        assert overview["unknown"] == 1
        assert overview["percent_vulnerable"] == 50.0
        assert overview["percent_safe"] == 25.0
        assert overview["percent_unknown"] == 25.0

    def test_percentage_all_safe(self, svc: PQCMigrationService) -> None:
        """100% safe when all findings are quantum-safe."""
        findings = [
            _finding(quantum_status="safe"),
            _finding(quantum_status="safe"),
        ]
        overview = svc.compute_overview(findings)
        assert overview["percent_safe"] == 100.0
        assert overview["percent_vulnerable"] == 0.0

    def test_percentage_all_vulnerable(self, svc: PQCMigrationService) -> None:
        """100% vulnerable when all findings are quantum-vulnerable."""
        findings = [
            _finding(quantum_status="vulnerable"),
            _finding(quantum_status="vulnerable"),
        ]
        overview = svc.compute_overview(findings)
        assert overview["percent_vulnerable"] == 100.0
        assert overview["percent_safe"] == 0.0


class TestAlgorithmFamilies:
    def test_families_grouped_correctly(self, svc: PQCMigrationService) -> None:
        """Should group findings by algorithm family and compute per-family progress."""
        findings = [
            _finding(algorithm_family="RSA", quantum_status="vulnerable"),
            _finding(algorithm_family="RSA", quantum_status="safe"),
            _finding(algorithm_family="ECDSA", quantum_status="vulnerable"),
            _finding(algorithm_family="AES", quantum_status="safe"),
            _finding(algorithm_family="AES", quantum_status="safe"),
        ]
        families = svc.compute_families(findings)
        family_map = {f["family"]: f for f in families}

        assert "RSA" in family_map
        assert family_map["RSA"]["total"] == 2
        assert family_map["RSA"]["vulnerable"] == 1
        assert family_map["RSA"]["safe"] == 1
        assert family_map["RSA"]["percent_migrated"] == 50.0

        assert "ECDSA" in family_map
        assert family_map["ECDSA"]["total"] == 1
        assert family_map["ECDSA"]["vulnerable"] == 1
        assert family_map["ECDSA"]["percent_migrated"] == 0.0

        assert "AES" in family_map
        assert family_map["AES"]["total"] == 2
        assert family_map["AES"]["safe"] == 2
        assert family_map["AES"]["percent_migrated"] == 100.0


class TestLaggingProjects:
    def test_lagging_projects_identified(self, svc: PQCMigrationService) -> None:
        """Projects with highest vulnerable percentage should be flagged as lagging."""
        proj_a = uuid.uuid4()
        proj_b = uuid.uuid4()
        findings = [
            _finding(project_id=proj_a, project_name="proj-a", quantum_status="vulnerable"),
            _finding(project_id=proj_a, project_name="proj-a", quantum_status="vulnerable"),
            _finding(project_id=proj_a, project_name="proj-a", quantum_status="safe"),
            _finding(project_id=proj_b, project_name="proj-b", quantum_status="safe"),
            _finding(project_id=proj_b, project_name="proj-b", quantum_status="safe"),
        ]
        lagging = svc.compute_lagging_projects(findings, limit=5)

        assert len(lagging) == 1  # only proj-a has vulnerabilities
        assert lagging[0]["project_name"] == "proj-a"
        assert lagging[0]["vulnerable_count"] == 2
        assert lagging[0]["total_count"] == 3
        assert abs(lagging[0]["percent_vulnerable"] - 66.67) < 0.1


class TestEmpty:
    def test_empty_findings(self, svc: PQCMigrationService) -> None:
        """Should handle empty finding list gracefully."""
        overview = svc.compute_overview([])
        assert overview["total_findings"] == 0
        assert overview["percent_vulnerable"] == 0.0
        assert overview["percent_safe"] == 0.0
        assert overview["percent_unknown"] == 0.0

        families = svc.compute_families([])
        assert families == []

        lagging = svc.compute_lagging_projects([])
        assert lagging == []
