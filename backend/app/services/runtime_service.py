"""Runtime enrichment service — OTel observation ingestion and finding enrichment (ADR-028)."""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.runtime_observation import RuntimeObservation as RuntimeObservationModel
from app.schemas.runtime import EnrichedFinding, RuntimeObservation, RuntimeSummary

logger = logging.getLogger(__name__)


class RuntimeService:
    """Manages runtime TLS/cipher observations and enriches static findings."""

    async def ingest_observation(
        self,
        session: AsyncSession,
        observation: RuntimeObservation,
        org_id: uuid.UUID,
    ) -> RuntimeObservationModel:
        """Store a runtime TLS/cipher observation linked to a project."""
        record = RuntimeObservationModel(
            project_id=observation.project_id,
            org_id=org_id,
            service_name=observation.service_name,
            tls_version=observation.tls_version,
            cipher_suite=observation.cipher_suite,
            peer_cert_subject=observation.peer_cert_subject,
            observed_at=observation.timestamp,
        )
        session.add(record)
        await session.flush()
        return record

    async def ingest_batch(
        self,
        session: AsyncSession,
        observations: list[RuntimeObservation],
        org_id: uuid.UUID,
    ) -> int:
        """Ingest a batch of runtime observations. Returns count of records created."""
        count = 0
        for obs in observations:
            await self.ingest_observation(session, obs, org_id)
            count += 1
        await session.commit()
        return count

    async def get_enriched_findings(
        self,
        session: AsyncSession,
        scan_id: uuid.UUID,
    ) -> list[EnrichedFinding]:
        """Get findings enriched with runtime observations (configured vs observed)."""
        # Load findings for the scan
        findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
        findings_result = await session.execute(findings_stmt)
        findings = list(findings_result.scalars().all())

        if not findings:
            return []

        # Collect project IDs from findings to fetch runtime observations
        project_ids = {f.project_id for f in findings}

        # Load runtime observations for those projects
        obs_stmt = select(RuntimeObservationModel).where(
            RuntimeObservationModel.project_id.in_(project_ids),
        )
        obs_result = await session.execute(obs_stmt)
        observations = list(obs_result.scalars().all())

        # Build lookup: service_name -> list of observations
        obs_by_service: dict[str, list[RuntimeObservationModel]] = {}
        for obs in observations:
            obs_by_service.setdefault(obs.service_name, []).append(obs)

        # Build lookup of observed cipher suites and TLS versions
        observed_ciphers: set[str] = set()
        observed_tls: set[str] = set()
        for obs in observations:
            if obs.cipher_suite:
                observed_ciphers.add(obs.cipher_suite.upper())
            if obs.tls_version:
                observed_tls.add(obs.tls_version)

        enriched: list[EnrichedFinding] = []
        for finding in findings:
            # Try to match finding to runtime observation
            finding_name_lower = finding.name.lower()
            runtime_observed = False
            obs_tls: str | None = None
            obs_cipher: str | None = None
            mismatch = False

            # Check if any observation's cipher/TLS matches the finding's algorithm
            for obs in observations:
                if obs.cipher_suite and obs.cipher_suite.upper() in finding_name_lower.upper():
                    runtime_observed = True
                    obs_cipher = obs.cipher_suite
                    obs_tls = obs.tls_version
                    break
                if obs.tls_version and f"tls {obs.tls_version}" in finding_name_lower:
                    runtime_observed = True
                    obs_tls = obs.tls_version
                    obs_cipher = obs.cipher_suite
                    break

            # If not matched by name, check if the finding's properties mention a service
            if not runtime_observed:
                props = finding.properties or {}
                service = props.get("service_name", "")
                if service and service in obs_by_service:
                    runtime_observed = True
                    latest_obs = max(obs_by_service[service], key=lambda o: o.observed_at)
                    obs_tls = latest_obs.tls_version
                    obs_cipher = latest_obs.cipher_suite

            # Detect mismatch: if finding mentions a specific TLS version/cipher
            # that differs from what was observed
            if runtime_observed and obs_tls:
                props = finding.properties or {}
                configured_tls = props.get("tls_version", "")
                if configured_tls and configured_tls != obs_tls:
                    mismatch = True

            enriched.append(
                EnrichedFinding(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    name=finding.name,
                    severity=finding.severity,
                    location_file=finding.location_file,
                    location_line=finding.location_line,
                    runtime_observed=runtime_observed,
                    observed_tls_version=obs_tls,
                    observed_cipher=obs_cipher,
                    mismatch=mismatch,
                )
            )

        return enriched

    async def get_runtime_summary(
        self,
        session: AsyncSession,
        project_id: uuid.UUID,
    ) -> RuntimeSummary:
        """Summary: observed TLS versions, cipher suites, cert chains across all services."""
        stmt = select(RuntimeObservationModel).where(
            RuntimeObservationModel.project_id == project_id,
        )
        result = await session.execute(stmt)
        observations = list(result.scalars().all())

        tls_versions: set[str] = set()
        cipher_suites: set[str] = set()
        services: set[str] = set()

        for obs in observations:
            if obs.tls_version:
                tls_versions.add(obs.tls_version)
            if obs.cipher_suite:
                cipher_suites.add(obs.cipher_suite)
            services.add(obs.service_name)

        return RuntimeSummary(
            project_id=project_id,
            total_observations=len(observations),
            unique_tls_versions=sorted(tls_versions),
            unique_cipher_suites=sorted(cipher_suites),
            services_observed=sorted(services),
            mismatches=0,  # Mismatches are computed at enrichment time
        )
