"""Tests for cross-scan finding matcher service (ADR-034)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.finding import Finding
from app.services.finding_matcher import FindingMatcher, MatchResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    project_id: uuid.UUID | None = None,
    fingerprint: str = "abc123",
    status: str = "open",
    location_line: int = 10,
    reopen_count: int = 0,
    last_reopened_at: datetime | None = None,
) -> Finding:
    """Create a mock Finding with the fields needed for matching."""
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.project_id = project_id or uuid.uuid4()
    f.fingerprint = fingerprint
    f.status = status
    f.location_line = location_line
    f.reopen_count = reopen_count
    f.last_reopened_at = last_reopened_at
    f.name = "AES-256"
    f.scan_id = uuid.uuid4()
    f.org_id = uuid.uuid4()
    f.rule_id = "cbom-go-aes"
    f.severity = "medium"
    f.confidence = "high"
    f.quantum_status = "safe"
    f.asset_type = "algorithm"
    f.location_file = "crypto/aes.go"
    f.properties = None
    f.normalized_signature = None
    f.assigned_to = None
    return f


def _make_new_finding(
    *,
    fingerprint: str = "abc123",
    location_line: int = 20,
    location_file: str = "crypto/aes.go",
    name: str = "AES-256",
) -> dict:
    """Create a new finding dict as would arrive from a CLI scan."""
    return {
        "fingerprint": fingerprint,
        "name": name,
        "rule_id": "cbom-go-aes",
        "severity": "medium",
        "confidence": "high",
        "quantum_status": "safe",
        "asset_type": "algorithm",
        "location_file": location_file,
        "location_line": location_line,
        "properties": None,
        "normalized_signature": None,
    }


def _mock_session_with_findings(existing: list[Finding]) -> AsyncMock:
    """Build an AsyncMock session that returns *existing* from execute().

    Mocks the query path: session.execute(...) -> result.scalars().all() -> existing
    """
    session = AsyncMock()
    result_mock = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = existing
    result_mock.scalars.return_value = scalars_mock
    session.execute.return_value = result_mock
    return session


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def matcher() -> FindingMatcher:
    return FindingMatcher()


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExactMatchPreservesStatus:
    """Existing finding matched by fingerprint should keep its status."""

    @pytest.mark.asyncio
    async def test_exact_match_preserves_status(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(project_id=project_id, fingerprint="fp1", status="in_review")
        session = _mock_session_with_findings([existing])

        new_findings = [_make_new_finding(fingerprint="fp1", location_line=55)]

        result = await matcher.match(project_id, new_findings, session)

        assert len(result.matched) == 1
        assert len(result.new) == 0
        assert len(result.resolved) == 0

        # Status must remain 'in_review'
        matched_existing = result.matched[0][1]
        assert matched_existing.status == "in_review"


class TestNewFindingCreatedAsOpen:
    """Unmatched new finding should be flagged as new (to be created with status 'open')."""

    @pytest.mark.asyncio
    async def test_new_finding_created_as_open(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        session = _mock_session_with_findings([])

        new_findings = [_make_new_finding(fingerprint="brand_new")]

        result = await matcher.match(project_id, new_findings, session)

        assert len(result.new) == 1
        assert result.new[0]["fingerprint"] == "brand_new"
        assert len(result.matched) == 0
        assert len(result.resolved) == 0


class TestUnmatchedOpenBecomesResolved:
    """Existing 'open' finding not present in new scan should be resolved."""

    @pytest.mark.asyncio
    async def test_unmatched_open_becomes_resolved(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(project_id=project_id, fingerprint="old_fp", status="open")
        session = _mock_session_with_findings([existing])

        # No new findings match 'old_fp'
        new_findings = [_make_new_finding(fingerprint="different_fp")]

        result = await matcher.match(project_id, new_findings, session)

        assert len(result.resolved) == 1
        assert result.resolved[0].fingerprint == "old_fp"

    @pytest.mark.asyncio
    async def test_unmatched_in_review_becomes_resolved(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(project_id=project_id, fingerprint="old_fp", status="in_review")
        session = _mock_session_with_findings([existing])

        result = await matcher.match(project_id, [], session)

        assert len(result.resolved) == 1

    @pytest.mark.asyncio
    async def test_unmatched_in_progress_becomes_resolved(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(project_id=project_id, fingerprint="old_fp", status="in_progress")
        session = _mock_session_with_findings([existing])

        result = await matcher.match(project_id, [], session)

        assert len(result.resolved) == 1


class TestUnmatchedFalsePositiveStays:
    """Existing 'false_positive' finding not in new scan stays 'false_positive'."""

    @pytest.mark.asyncio
    async def test_unmatched_fp_stays_fp(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(
            project_id=project_id, fingerprint="fp_finding", status="false_positive"
        )
        session = _mock_session_with_findings([existing])

        result = await matcher.match(project_id, [], session)

        assert len(result.resolved) == 0
        assert len(result.matched) == 0
        assert len(result.new) == 0


class TestUnmatchedRiskAcceptedStays:
    """Existing 'risk_accepted' finding not in new scan stays 'risk_accepted'."""

    @pytest.mark.asyncio
    async def test_unmatched_ra_stays_ra(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(
            project_id=project_id, fingerprint="ra_finding", status="risk_accepted"
        )
        session = _mock_session_with_findings([existing])

        result = await matcher.match(project_id, [], session)

        assert len(result.resolved) == 0
        assert len(result.matched) == 0
        assert len(result.new) == 0


class TestReopenResolvedFinding:
    """Previously resolved finding matched again should reopen."""

    @pytest.mark.asyncio
    async def test_reopen_resolved_finding(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(
            project_id=project_id,
            fingerprint="was_resolved",
            status="resolved",
            reopen_count=0,
        )
        session = _mock_session_with_findings([existing])

        new_findings = [_make_new_finding(fingerprint="was_resolved")]

        result = await matcher.match(project_id, new_findings, session)

        assert len(result.matched) == 1
        reopened = result.matched[0][1]
        assert reopened.status == "open"
        assert reopened.reopen_count == 1
        assert reopened.last_reopened_at is not None

    @pytest.mark.asyncio
    async def test_reopen_increments_existing_count(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        """Reopen count should increment from existing value, not reset."""
        existing = _make_finding(
            project_id=project_id,
            fingerprint="multi_reopen",
            status="resolved",
            reopen_count=3,
        )
        session = _mock_session_with_findings([existing])

        new_findings = [_make_new_finding(fingerprint="multi_reopen")]

        result = await matcher.match(project_id, new_findings, session)

        reopened = result.matched[0][1]
        assert reopened.reopen_count == 4


class TestLineNumberUpdatedOnMatch:
    """Matched finding should get its line number updated from the new scan."""

    @pytest.mark.asyncio
    async def test_line_number_updated_on_match(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing = _make_finding(
            project_id=project_id, fingerprint="same_fp", location_line=10
        )
        session = _mock_session_with_findings([existing])

        new_findings = [_make_new_finding(fingerprint="same_fp", location_line=42)]

        result = await matcher.match(project_id, new_findings, session)

        matched_existing = result.matched[0][1]
        assert matched_existing.location_line == 42


class TestEmptyNewFindings:
    """When new scan has no findings, all existing open findings should resolve."""

    @pytest.mark.asyncio
    async def test_empty_new_findings(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        existing_open = _make_finding(
            project_id=project_id, fingerprint="fp1", status="open"
        )
        existing_in_review = _make_finding(
            project_id=project_id, fingerprint="fp2", status="in_review"
        )
        existing_ra = _make_finding(
            project_id=project_id, fingerprint="fp3", status="risk_accepted"
        )
        session = _mock_session_with_findings([existing_open, existing_in_review, existing_ra])

        result = await matcher.match(project_id, [], session)

        # open and in_review should resolve; risk_accepted should not
        assert len(result.resolved) == 2
        resolved_fps = {f.fingerprint for f in result.resolved}
        assert resolved_fps == {"fp1", "fp2"}
        assert len(result.matched) == 0
        assert len(result.new) == 0


class TestEmptyExistingFindings:
    """When DB has no existing findings, all new findings are new."""

    @pytest.mark.asyncio
    async def test_empty_existing_findings(
        self, matcher: FindingMatcher, project_id: uuid.UUID
    ) -> None:
        session = _mock_session_with_findings([])

        new_findings = [
            _make_new_finding(fingerprint="new1"),
            _make_new_finding(fingerprint="new2"),
            _make_new_finding(fingerprint="new3"),
        ]

        result = await matcher.match(project_id, new_findings, session)

        assert len(result.new) == 3
        assert len(result.matched) == 0
        assert len(result.resolved) == 0
