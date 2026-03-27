"""Tests for CertificateTrackerService — certificate expiry tracking from findings."""

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.certificate_tracker_service import CertificateTrackerService


def _cert_finding(
    *,
    subject: str = "api.example.com",
    issuer: str = "Let's Encrypt",
    not_valid_after: datetime | None = None,
    project_name: str = "auth-service",
    file_path: str = "certs/server.pem",
) -> SimpleNamespace:
    """Create a minimal certificate finding for testing."""
    now = datetime.now(timezone.utc)
    if not_valid_after is None:
        not_valid_after = now + timedelta(days=120)
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=f"Certificate: {subject}",
        asset_type="certificate",
        location_file=file_path,
        project_id=uuid.uuid4(),
        org_id=uuid.uuid4(),
        properties={
            "subject_name": subject,
            "issuer_name": issuer,
            "not_valid_after": not_valid_after.isoformat(),
        },
        project=SimpleNamespace(name=project_name, id=uuid.uuid4()),
    )


@pytest.fixture
def svc() -> CertificateTrackerService:
    return CertificateTrackerService()


class TestStatusColorLogic:
    def test_green_cert(self, svc: CertificateTrackerService) -> None:
        """Certificate >90 days from expiry should be green."""
        future = datetime.now(timezone.utc) + timedelta(days=120)
        color, days = svc.compute_status(future)
        assert color == "green"
        assert days > 90

    def test_amber_cert(self, svc: CertificateTrackerService) -> None:
        """Certificate 30-90 days from expiry should be amber."""
        future = datetime.now(timezone.utc) + timedelta(days=60)
        color, days = svc.compute_status(future)
        assert color == "amber"
        assert 30 <= days <= 90

    def test_red_cert(self, svc: CertificateTrackerService) -> None:
        """Certificate <30 days from expiry should be red."""
        future = datetime.now(timezone.utc) + timedelta(days=15)
        color, days = svc.compute_status(future)
        assert color == "red"
        assert 0 < days < 30

    def test_expired_cert(self, svc: CertificateTrackerService) -> None:
        """Expired certificate should be black."""
        past = datetime.now(timezone.utc) - timedelta(days=10)
        color, days = svc.compute_status(past)
        assert color == "black"
        assert days < 0


class TestFilterByStatus:
    @pytest.mark.asyncio
    async def test_filter_by_status(self, svc: CertificateTrackerService) -> None:
        """Filtering by status_color should return only matching entries."""
        now = datetime.now(timezone.utc)

        green_finding = _cert_finding(
            subject="green.example.com",
            not_valid_after=now + timedelta(days=120),
        )
        red_finding = _cert_finding(
            subject="red.example.com",
            not_valid_after=now + timedelta(days=10),
        )

        # Mock session that returns both findings
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [green_finding, red_finding]
        session.execute = AsyncMock(return_value=mock_result)

        # Test: build entries from findings
        entries = svc.build_entries([green_finding, red_finding])
        red_entries = [e for e in entries if e["status_color"] == "red"]
        green_entries = [e for e in entries if e["status_color"] == "green"]

        assert len(red_entries) == 1
        assert red_entries[0]["subject"] == "red.example.com"
        assert len(green_entries) == 1
        assert green_entries[0]["subject"] == "green.example.com"
