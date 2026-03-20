# SOC 2 Controls Checklist

This document maps CipherRadar's security controls to SOC 2 Type II trust service criteria. It covers audit logging, encryption, access controls, change management, availability, and incident response.

## Audit Logging (CC7.2, CC7.3)

### Events Logged

CipherRadar maintains a comprehensive audit log for all security-relevant operations. Every log entry includes timestamp (UTC), actor identity, source IP, resource ID, and result.

**Authentication and session events:**
- User login (success and failure)
- User logout
- Password change
- MFA enrollment and verification
- API key creation, rotation, and revocation
- OAuth token grant and refresh (GitHub, GitLab, Bitbucket, Jira)
- Session expiration and forced logout

**CRUD operations:**
- Organisation create, update, delete
- Group create, update, delete
- Project create, update, delete, archive
- User invite, role change, deactivation, removal
- Policy create, update, delete, enable, disable
- Notification preference changes
- Integration connect, disconnect, reconfigure

**Scan operations:**
- Scan triggered (manual, webhook, scheduled)
- Scan queued, started, completed, failed, cancelled
- CBOM document generated
- CBOM document signed (Sigstore cosign)
- CBOM export (JSON, PDF, SARIF, SonarQube generic)
- Scan upload (manual CBOM import)

**Policy and compliance events:**
- Policy evaluation executed
- Policy violation detected
- Finding suppression submitted, approved, rejected, expired
- Compliance report generated
- Compliance framework mapping updated

**Administrative events:**
- System configuration changes
- Worker scaling events
- Database migration execution
- Backup and restore operations

### Log format

All audit logs are structured JSON, suitable for ingestion by SIEM systems:

```json
{
  "timestamp": "2026-03-21T14:30:00.000Z",
  "level": "INFO",
  "event": "scan.completed",
  "actor_id": "user-uuid",
  "actor_type": "user",
  "org_id": "org-uuid",
  "resource_type": "scan",
  "resource_id": "scan-uuid",
  "source_ip": "192.0.2.1",
  "user_agent": "Mozilla/5.0...",
  "details": {
    "project_id": "project-uuid",
    "findings_count": 42,
    "duration_seconds": 120
  },
  "result": "success"
}
```

### Retention

- Audit logs are retained for a minimum of 1 year (configurable via `CBOM_AUDIT_LOG_RETENTION_DAYS`)
- Logs are immutable once written (append-only table with no UPDATE/DELETE permissions for the application role)
- Export to external SIEM (Splunk, Elastic, Datadog) via structured log shipping

## Encryption at Rest (CC6.1, CC6.7)

### Database

**PostgreSQL Transparent Data Encryption (TDE):**
- All data files, WAL, and temporary files are encrypted using AES-256
- Key management via cloud provider KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault)
- For self-hosted deployments, use PostgreSQL TDE with a KMIP-compliant key manager

**Application-level encryption for sensitive fields:**
- Integration credentials (Jira OAuth tokens, Dependency-Track API keys, git provider tokens) are encrypted at the application layer using AES-256-GCM before storage
- Encryption keys are stored in the configured KMS, never in the database or environment variables
- Key rotation is supported without downtime via envelope encryption

### Object Storage (CBOM documents)

- S3-compatible storage (production `cbom_store_type=s3`) uses SSE-S3 or SSE-KMS encryption
- Bucket policies enforce `aws:SecureTransport` (TLS-only access)
- Versioning is enabled for CBOM document immutability

### Backups

- Database backups are encrypted using the same KMS key as TDE
- Backup encryption is verified as part of restore testing (quarterly)

## Encryption in Transit (CC6.1, CC6.7)

### TLS Configuration

All network communication uses TLS 1.3 (minimum TLS 1.2 for legacy client compatibility):

| Connection                     | Protocol | Minimum Version |
|-------------------------------|----------|----------------|
| Client to API (FastAPI)        | TLS      | 1.3            |
| Client to frontend (React SPA) | TLS      | 1.3            |
| API to PostgreSQL              | TLS      | 1.2            |
| API to Redis                   | TLS      | 1.2            |
| Worker to PostgreSQL           | TLS      | 1.2            |
| Worker to Redis                | TLS      | 1.2            |
| API to external integrations   | TLS      | 1.2            |
| WebSocket connections          | WSS      | 1.3            |

### Certificate management

- Ingress TLS termination via cert-manager with Let's Encrypt or organisational CA
- Internal service-to-service communication uses mTLS via service mesh (Istio/Linkerd) when deployed in Kubernetes
- Certificate expiry monitoring via Prometheus `cipherradar_cert_expiry_seconds` gauge

### Cipher suites

Preferred cipher suites (in order):
1. TLS_AES_256_GCM_SHA384
2. TLS_CHACHA20_POLY1305_SHA256
3. TLS_AES_128_GCM_SHA256

## Access Controls (CC6.1, CC6.2, CC6.3)

### Row-Level Security (RLS)

PostgreSQL RLS policies enforce tenant isolation at the database level:

- All queries are scoped to the authenticated user's organisation via `org_id`
- RLS policies are defined on all multi-tenant tables (scans, projects, groups, findings, policies, notifications)
- The application database role cannot bypass RLS (`NOBYPASSRLS`)
- RLS policies are tested in the CI pipeline to prevent regressions

### Role-Based Access Control (RBAC)

CipherRadar implements a hierarchical RBAC model:

| Role           | Permissions                                                     |
|---------------|----------------------------------------------------------------|
| Viewer         | Read scans, findings, compliance reports                        |
| Developer      | Viewer + trigger scans, export CBOMs                           |
| Security Lead  | Developer + manage policies, approve suppressions              |
| Admin          | Security Lead + manage users, groups, integrations, org settings|
| Owner          | Admin + billing, delete organisation, transfer ownership        |

Additional controls:
- API keys are scoped to read-only operations (no `policy:write` scope per OQ-RBAC-7)
- All role changes require Admin or Owner role
- Role changes are audit-logged

### Authentication

- JWT-based authentication (HS256, 15-minute access tokens, 7-day refresh tokens)
- Passwords hashed with bcrypt (cost factor 12)
- MFA support via TOTP (RFC 6238)
- OAuth 2.0 SSO via GitHub, GitLab, Bitbucket
- API key authentication for CI/CD integrations (read-only scope)

### Session management

- Access tokens expire after 15 minutes (configurable via `CBOM_JWT_ACCESS_TOKEN_EXPIRE_MINUTES`)
- Refresh tokens expire after 7 days (configurable via `CBOM_JWT_REFRESH_TOKEN_EXPIRE_DAYS`)
- Forced session invalidation on password change
- Maximum 5 concurrent sessions per user

## Change Management (CC8.1)

### Git-based configuration

- All detection rules, library models, and compliance framework mappings are version-controlled in the `scanner/` directory
- Policy definitions are stored as code and deployed via the standard release process
- Infrastructure configuration is managed via Helm charts in `deploy/`

### Immutable CBOM snapshots

- Every scan produces an immutable CBOM document
- CBOM documents are signed using Sigstore cosign (keyless mode) for tamper-evidence
- Signatures are recorded in the Sigstore Rekor transparency log
- CBOM documents cannot be modified or deleted through the application API
- Historical CBOMs enable diff-based tracking of cryptographic posture changes over time

### Release process

- All code changes require pull request review (minimum 1 approver)
- CI pipeline enforces: lint, type check, test, security scan (gosec/bandit), dependency audit
- Semantic versioning for CLI and backend releases
- GoReleaser produces signed, reproducible build artifacts
- Database migrations are versioned via Alembic with forward-only policy

## Availability (A1.1, A1.2)

### Health endpoints

CipherRadar exposes health check endpoints for monitoring and orchestration:

| Endpoint              | Purpose                                    |
|----------------------|-------------------------------------------|
| `GET /api/v1/health` | Overall service health (database + Redis) |
| `GET /api/v1/metrics`| Prometheus metrics (see below)            |

The health endpoint returns structured status for each dependency:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "checks": {
    "database": "connected",
    "redis": "connected"
  }
}
```

Kubernetes readiness and liveness probes should target `/api/v1/health`.

### Recommended monitoring (Prometheus)

Key metrics exported at `/api/v1/metrics`:

**Counters:**
- `scans_total` — total scans by status (completed, failed, cancelled)
- `findings_total` — total findings by severity
- `notifications_sent_total` — notifications by channel and trigger type

**Gauges:**
- `active_scans` — currently running scans
- `queue_depth` — scans waiting in the queue
- `portfolio_quantum_risk_score` — organisation-level quantum readiness score

**Histograms:**
- `scan_duration_seconds` — scan execution time distribution
- `api_response_duration_seconds` — API latency distribution

### Recommended alerts

| Alert                          | Condition                                  | Severity |
|-------------------------------|-------------------------------------------|----------|
| ServiceDown                    | health endpoint unreachable for 2 min      | Critical |
| DatabaseDisconnected           | health check `database=disconnected` 1 min | Critical |
| RedisDisconnected              | health check `redis=disconnected` 2 min    | High     |
| ScanQueueBacklog               | queue_depth > 100 for 5 min               | Warning  |
| ScanFailureRate                | scan failure rate > 10% over 15 min       | High     |
| APILatencyHigh                 | p99 > 2s for 5 min                        | Warning  |
| CertificateExpiringSoon        | cert_expiry < 14 days                     | High     |

### Backup and recovery

- PostgreSQL: daily automated backups with point-in-time recovery (PITR)
- Redis: AOF persistence with `appendfsync everysec`
- CBOM object store: versioned bucket with cross-region replication (production)
- Recovery time objective (RTO): 1 hour
- Recovery point objective (RPO): 1 minute (with PITR)

## Incident Response (CC7.3, CC7.4)

### Notification triggers for security events

CipherRadar generates automated notifications for security-relevant events via in-app, email, and Microsoft Teams channels:

| Trigger                          | Channel        | Severity |
|---------------------------------|---------------|----------|
| Critical finding detected        | All channels   | Critical |
| Policy violation on scan         | All channels   | High     |
| Certificate expiry within 30 days| Email + Teams  | High     |
| Scan failure                     | In-app + email | Medium   |
| Suppression submitted for review | In-app         | Medium   |
| Integration disconnected         | Email + Teams  | High     |
| Unusual scan volume (anomaly)    | Email + Teams  | Medium   |

### Escalation

- Critical findings trigger immediate notifications to all Security Lead and Admin users in the organisation
- Policy violations create Jira tickets automatically (when Jira integration is connected) with deduplication
- Unacknowledged critical notifications are re-sent after 4 hours

### Forensic support

- All audit log entries are retained for 1+ year
- CBOM snapshots provide a historical record of cryptographic posture at any point in time
- Scan metadata includes branch, commit SHA, and detection pass configuration for reproducibility
- CBOM signatures provide non-repudiation via the Rekor transparency log
