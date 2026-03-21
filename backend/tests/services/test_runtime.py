"""Tests for RuntimeService — observation ingestion and enrichment matching."""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.schemas.runtime import RuntimeObservation
from app.services.runtime_service import RuntimeService


def _observation(
    service_name: str = "payment-svc",
    tls_version: str | None = "1.3",
    cipher_suite: str | None = "TLS_AES_256_GCM_SHA384",
    peer_cert_subject: str | None = None,
    project_id: uuid.UUID | None = None,
) -> RuntimeObservation:
    return RuntimeObservation(
        service_name=service_name,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        peer_cert_subject=peer_cert_subject,
        timestamp=datetime.now(tz=timezone.utc),
        project_id=project_id or uuid.uuid4(),
    )


def _finding_model(
    name: str = "AES-256 encryption",
    severity: str = "medium",
    rule_id: str = "cbom-java-aes",
    location_file: str = "src/Crypto.java",
    location_line: int = 42,
    properties: dict | None = None,
    scan_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        severity=severity,
        rule_id=rule_id,
        location_file=location_file,
        location_line=location_line,
        properties=properties or {},
        scan_id=scan_id or uuid.uuid4(),
        project_id=project_id or uuid.uuid4(),
    )


def _obs_model(
    service_name: str = "payment-svc",
    tls_version: str | None = "1.3",
    cipher_suite: str | None = "TLS_AES_256_GCM_SHA384",
    peer_cert_subject: str | None = None,
    project_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        service_name=service_name,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        peer_cert_subject=peer_cert_subject,
        project_id=project_id or uuid.uuid4(),
        observed_at=observed_at or datetime.now(tz=timezone.utc),
    )


@pytest.fixture
def svc() -> RuntimeService:
    return RuntimeService()


class TestIngestObservation:
    @pytest.mark.asyncio
    async def test_ingest_creates_record(self, svc: RuntimeService) -> None:
        """Ingesting an observation should add a record to the session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()

        obs = _observation()
        org_id = uuid.uuid4()

        record = await svc.ingest_observation(session, obs, org_id)

        session.add.assert_called_once()
        session.flush.assert_awaited_once()
        assert record.service_name == obs.service_name
        assert record.tls_version == obs.tls_version
        assert record.cipher_suite == obs.cipher_suite

    @pytest.mark.asyncio
    async def test_ingest_batch_returns_count(self, svc: RuntimeService) -> None:
        """Batch ingestion should return the count of records created."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()

        project_id = uuid.uuid4()
        observations = [
            _observation(service_name="svc-a", project_id=project_id),
            _observation(service_name="svc-b", project_id=project_id),
            _observation(service_name="svc-c", project_id=project_id),
        ]
        org_id = uuid.uuid4()

        count = await svc.ingest_batch(session, observations, org_id)

        assert count == 3
        assert session.add.call_count == 3
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ingest_empty_batch(self, svc: RuntimeService) -> None:
        """Empty batch should return 0."""
        session = AsyncMock()
        session.commit = AsyncMock()

        count = await svc.ingest_batch(session, [], uuid.uuid4())
        assert count == 0


class TestGetRuntimeSummary:
    @pytest.mark.asyncio
    async def test_summary_aggregates_observations(self, svc: RuntimeService) -> None:
        """Summary should aggregate unique TLS versions, cipher suites, and services."""
        project_id = uuid.uuid4()
        obs_list = [
            _obs_model(service_name="svc-a", tls_version="1.3", cipher_suite="TLS_AES_256_GCM_SHA384", project_id=project_id),
            _obs_model(service_name="svc-b", tls_version="1.2", cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA", project_id=project_id),
            _obs_model(service_name="svc-a", tls_version="1.3", cipher_suite="TLS_AES_256_GCM_SHA384", project_id=project_id),
        ]

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = obs_list

        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        summary = await svc.get_runtime_summary(session, project_id)

        assert summary.project_id == project_id
        assert summary.total_observations == 3
        assert set(summary.unique_tls_versions) == {"1.2", "1.3"}
        assert len(summary.unique_cipher_suites) == 2
        assert set(summary.services_observed) == {"svc-a", "svc-b"}

    @pytest.mark.asyncio
    async def test_summary_empty_project(self, svc: RuntimeService) -> None:
        """Summary for a project with no observations."""
        project_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []

        session = AsyncMock()
        session.execute = AsyncMock(return_value=mock_result)

        summary = await svc.get_runtime_summary(session, project_id)

        assert summary.total_observations == 0
        assert summary.unique_tls_versions == []
        assert summary.unique_cipher_suites == []
        assert summary.services_observed == []


class TestEnrichedFindings:
    @pytest.mark.asyncio
    async def test_enrichment_with_matching_service(self, svc: RuntimeService) -> None:
        """Finding with matching service_name in properties should be enriched."""
        project_id = uuid.uuid4()
        scan_id = uuid.uuid4()

        finding = _finding_model(
            name="TLS configuration",
            properties={"service_name": "payment-svc"},
            scan_id=scan_id,
            project_id=project_id,
        )

        obs = _obs_model(
            service_name="payment-svc",
            tls_version="1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            project_id=project_id,
        )

        # Mock session with two execute calls: findings, then observations
        findings_result = MagicMock()
        findings_result.scalars.return_value.all.return_value = [finding]

        obs_result = MagicMock()
        obs_result.scalars.return_value.all.return_value = [obs]

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[findings_result, obs_result])

        enriched = await svc.get_enriched_findings(session, scan_id)

        assert len(enriched) == 1
        assert enriched[0].runtime_observed is True
        assert enriched[0].observed_tls_version == "1.3"
        assert enriched[0].observed_cipher == "TLS_AES_256_GCM_SHA384"

    @pytest.mark.asyncio
    async def test_enrichment_no_observations(self, svc: RuntimeService) -> None:
        """Findings without matching observations should not be enriched."""
        scan_id = uuid.uuid4()
        project_id = uuid.uuid4()

        finding = _finding_model(scan_id=scan_id, project_id=project_id)

        findings_result = MagicMock()
        findings_result.scalars.return_value.all.return_value = [finding]

        obs_result = MagicMock()
        obs_result.scalars.return_value.all.return_value = []

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[findings_result, obs_result])

        enriched = await svc.get_enriched_findings(session, scan_id)

        assert len(enriched) == 1
        assert enriched[0].runtime_observed is False
        assert enriched[0].observed_tls_version is None

    @pytest.mark.asyncio
    async def test_enrichment_empty_scan(self, svc: RuntimeService) -> None:
        """Scan with no findings returns empty list."""
        scan_id = uuid.uuid4()

        findings_result = MagicMock()
        findings_result.scalars.return_value.all.return_value = []

        session = AsyncMock()
        session.execute = AsyncMock(return_value=findings_result)

        enriched = await svc.get_enriched_findings(session, scan_id)
        assert enriched == []
