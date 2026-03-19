# ADR-012: Backend Database Schema — CBOMStore, TimescaleDB Hypertables, JSONB Strategy

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-19 |
| **Deciders** | Architecture session |

---

## Context

The backend needs a database schema to store organisations, projects, scans, CBOM documents, findings, and compliance data. Three key design questions required resolution:

1. **CBOM document storage** — CBOM JSON documents can be large (multi-MB per scan). Storing them directly in PostgreSQL columns does not scale beyond early development. A storage abstraction is needed that supports both simple development workflows and production-grade object storage.
2. **Time-series scan metrics** — Scan counts, finding trends, and compliance scores change over time and must support efficient time-range queries for dashboards and reporting. Standard relational tables are not optimised for this access pattern.
3. **Flexible crypto metadata** — Cryptographic findings have properties that vary by asset type (algorithm parameters, key sizes, quantum status, protocol versions) and will evolve as CycloneDX and detection rules mature. A rigid normalised schema would require frequent migrations.

This also resolves several open questions from the architecture sessions: D-001 (data retention and hot/warm/cold model) and A-001 (PostgreSQL CTEs before Neo4j).

---

## Decisions

### 1. CBOMStore Abstraction

CBOM JSON documents are never stored directly in a PostgreSQL column in production. A `CBOMStore` interface abstracts storage with two implementations:

| Implementation | Storage | Use Case | Threshold |
|---|---|---|---|
| **`PostgresCBOMStore`** | JSONB column in `cbom_documents` table | Development, early stage | < 10 GB total CBOM storage, < 500 scans/day |
| **`S3CBOMStore`** | MinIO/S3 object storage; Postgres holds a URI pointer | Production | Above either threshold |

Both implementations expose the same interface — switching is a configuration change, not a code change. The `cbom_documents` table always stores a `storage_uri` field; for `PostgresCBOMStore`, this is a self-referencing pointer to the same row's JSONB column.

### 2. TimescaleDB Hypertables

The `scan_metrics` table is a TimescaleDB hypertable partitioned on the `time` column. This enables:

- Efficient time-range queries for dashboards (e.g., "findings trend over last 90 days")
- Automatic chunk-based data compression for the warm tier (90 days+)
- Continuous aggregates for pre-computed rollups (daily/weekly summaries)
- Native retention policies aligned with the hot/warm/cold model from D-001

Standard PostgreSQL tables are used for all non-time-series data.

### 3. JSONB + GIN Indexes

Findings are stored with a JSONB `properties` column for flexible cryptographic metadata (algorithm parameters, key sizes, protocol details, quantum properties). GIN indexes on JSONB columns enable fast filtering by algorithm, quantum status, severity, and other properties without requiring schema migrations when new property types are added.

### 4. Graph Abstraction Layer (GAL)

All graph queries (dependency graphs, crypto asset relationships, call chains) go through a `GraphRepository` interface. Phase 1–2 implementation uses PostgreSQL recursive CTEs. No raw CTE queries are permitted outside `GraphRepository`. This ensures a clean migration path to Neo4j in Phase 3 — the `GraphRepository` interface remains stable, only the implementation changes.

### Schema Overview

Key tables:

| Table | Purpose | Key Columns |
|---|---|---|
| `organisations` | Top-level tenant | id, name, plan, settings (JSONB) |
| `groups` | Hierarchical grouping within an org | id, org_id, parent_group_id (nullable, for nesting), name |
| `projects` | A scannable codebase | id, group_id, name, git_url, provider, settings (JSONB) |
| `scans` | A single scan execution | id, project_id, status (queued/running/completed/failed), branch, commit_sha, started_at, completed_at, findings_count |
| `cbom_documents` | CBOM output per scan | id, scan_id, storage_uri, spec_version, serial_number |
| `findings` | Individual crypto findings | id, scan_id, project_id, rule_id, name, severity, confidence, quantum_status, asset_type, location_file, location_line, properties (JSONB) |
| `scan_metrics` | Time-series scan statistics (hypertable) | time (timestamptz), project_id, findings_count, critical_count, high_count, quantum_risk_score, compliance_score |
| `policy_sets` | Policy rules per org | id, org_id, name, rules (JSONB) |
| `compliance_mappings` | Framework compliance status per algorithm | id, framework, algorithm, classification, status |

---

## Rationale

### CBOMStore abstraction
Storing multi-MB CBOM JSON in PostgreSQL JSONB columns works for development and small deployments but degrades at scale — table bloat, VACUUM pressure, backup size, and replication lag all increase. Object storage (MinIO/S3) is purpose-built for large immutable blobs. The abstraction avoids premature infrastructure complexity during development while ensuring a clean production path. The threshold of ~10 GB / ~500 scans per day is based on the point where PostgreSQL JSONB storage overhead becomes operationally noticeable.

### TimescaleDB hypertables
Scan metrics are a natural time-series workload: append-mostly writes, time-range reads, aggregation queries. TimescaleDB extends PostgreSQL (no separate database) and provides automatic partitioning, compression, and continuous aggregates. This avoids the operational overhead of a separate time-series database while delivering the query performance dashboards require.

### JSONB + GIN indexes
Cryptographic findings have heterogeneous properties — an AES finding has different metadata than an RSA certificate or a TLS configuration. A fully normalised schema would require either a wide table with many nullable columns or an EAV pattern, both of which are worse than JSONB for this use case. GIN indexes provide sub-millisecond lookups on JSONB keys without sacrificing flexibility.

### Graph Abstraction Layer
PostgreSQL recursive CTEs are sufficient for the graph query complexity expected in Phase 1–2 (dependency trees, transitive crypto usage). Neo4j becomes worthwhile when graph traversals span thousands of nodes or require pattern matching across multiple relationship types — expected in Phase 3 when cross-project analysis is introduced. Building the abstraction now costs minimal effort and avoids a painful migration later.

---

## Consequences

- **Positive:** CBOMStore abstraction enables dev-to-prod migration without code changes — configuration swap only
- **Positive:** TimescaleDB handles time-series scan metrics efficiently with automatic compression and continuous aggregates
- **Positive:** JSONB flexibility avoids rigid schema for crypto properties that will evolve with CycloneDX spec updates and new detection rules
- **Positive:** GAL ensures the Neo4j migration path in Phase 3 is clean — no scattered raw CTEs to find and replace
- **Negative:** JSONB queries are slower than normalised columns for complex joins — mitigated by GIN indexes and by keeping high-cardinality filter columns (severity, quantum_status, asset_type) as top-level table columns rather than JSONB-only
- **Negative:** Two storage backends (PostgresCBOMStore + S3CBOMStore) adds operational complexity — mitigated by clear threshold guidance and configuration-only switching

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/02-architecture.md` | Schema referenced in data layer section (§2.4); CBOMStore and GAL abstractions documented |
| `docs/12-phase2-implementation-plan.md` | B-M1 Agent-DBSchema implements this ADR; Alembic initial migration creates all tables listed here |
