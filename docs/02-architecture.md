# Architecture

> **Document version:** v3
> **Created:** 2026-03-15
> **Last updated:** 2026-03-18
> **Status:** Active

## Change History

| Version | Date | Change | Triggered By |
|---|---|---|---|
| v1 | 2026-03-15 | Initial document | — |
| v2 | 2026-03-17 | Added graph DB architecture §2.4.1–2.4.4; updated multi-tenant isolation note; linked RBAC doc | A-001 resolution |
| v3 | 2026-03-18 | Added CBOMStore abstraction §2.4.1; added hot/warm/cold storage tiers §2.4.2; renumbered §2.4.2–2.4.4 → §2.4.3–2.4.5 | D-001 resolution |

---

## 1. High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CipherRadar PLATFORM                           │
│                                                                             │
│  ┌─────────────────┐   ┌──────────────────────┐   ┌─────────────────────┐  │
│  │  INGESTION      │   │  DETECTION ENGINE     │   │  ANALYSIS ENGINE    │  │
│  │  LAYER          │──▶│  (multi-lang          │──▶│                     │  │
│  │                 │   │   scanners)           │   │  Risk Scoring       │  │
│  │  Git repos      │   │                       │   │  Quantum Classify   │  │
│  │  Local paths    │   │  AST Parser           │   │  Compliance Map     │  │
│  │  File upload    │   │  Taint Engine         │   │  Policy Evaluation  │  │
│  │  Container reg  │   │  Regex Layer          │   │  Misuse Detection   │  │
│  │  CI/CD trigger  │   │  Config Scanner       │   │                     │  │
│  │                 │   │  SBOM correlation      │   │                     │  │
│  └─────────────────┘   └──────────────────────┘   └──────────┬──────────┘  │
│                                                               │             │
│  ┌────────────────────────────────────────────────────────────▼──────────┐  │
│  │                    CBOM STORE  (Versioned)                            │  │
│  │   CycloneDX 1.7 JSON/XML  ·  Asset Graph  ·  History / Diff          │  │
│  └────────────────────────────────────────────────────────────┬──────────┘  │
│                                                               │             │
│  ┌─────────────────┐   ┌──────────────────────┐   ┌──────────▼──────────┐  │
│  │  REPORTING      │   │  INTEGRATIONS        │   │  DASHBOARD UI       │  │
│  │                 │   │                      │   │                     │  │
│  │  PDF            │   │  GitHub / GitLab     │   │  Portfolio view     │  │
│  │  SARIF          │   │  Jenkins             │   │  Asset explorer     │  │
│  │  CycloneDX JSON │   │  Jira / Linear       │   │  Dependency graph   │  │
│  │  SPDX           │   │  Slack / Teams       │   │  Migration wizard   │  │
│  │  HTML / CSV     │   │  SonarQube           │   │  Compliance maps    │  │
│  │  Signed CBOM    │   │  Dependency-Track    │   │  Cert calendar      │  │
│  └─────────────────┘   └──────────────────────┘   └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Breakdown

### 2.1 Ingestion Layer

Responsible for acquiring source code and preparing it for scanning.

| Component | Responsibility |
|---|---|
| **Git Connector** | Clone any Git URL (GitHub, GitLab, Bitbucket, self-hosted); branch-aware; shallow clone for speed |
| **Local Path Scanner** | Walk a local directory tree; respect `.gitignore` and `.cbomignore` |
| **File Upload Handler** | Accept ZIP/TAR archives via API |
| **Container Registry Connector** | Pull OCI image layers; extract filesystem for scanning |
| **CI/CD Trigger Handler** | Receive webhook events (push, PR open, PR merge); trigger incremental or full scan |
| **SBOM Ingestor** | Accept existing CycloneDX or SPDX SBOMs to correlate library versions with crypto usage |

### 2.2 Detection Engine

The core scanning logic. See [Detection Engine](03-detection-engine.md) for full detail.

| Sub-component | Responsibility |
|---|---|
| **Language Dispatcher** | Identify language from file extension + content sniffing; route to correct analyzer |
| **AST Parsers** | Language-specific parsers (tree-sitter backed); build ASTs for all supported languages |
| **Call Graph Builder** | Construct inter-procedural call graph for taint propagation |
| **Taint Engine** | Track data flow from sources (user input, config, constants) to crypto sinks |
| **Constant Resolver** | Resolve variable values to literals where statically determinable |
| **Regex Layer** | Fast path for PEM headers, key blobs, algorithm name strings, secret patterns |
| **Config File Scanner** | Parse nginx.conf, httpd.conf, openssl.cnf, java.security, k8s manifests, Dockerfiles |
| **Library API Model** | Per-language maps of crypto library function signatures → CBOM asset types |
| **Confidence Scorer** | Assign High / Medium / Low / Unresolved confidence to each finding |

### 2.3 Analysis Engine

Post-processing of raw detection findings into actionable intelligence.

| Sub-component | Responsibility |
|---|---|
| **Quantum Classifier** | Tag each algorithm with quantum vulnerability status and NIST PQC security level (0–6) |
| **Risk Scorer** | Compute per-service and portfolio-level risk scores |
| **Compliance Mapper** | Map findings to NIST SP 800-131A, FIPS 140-3, PCI-DSS, CNSA 2.0, ISO 27001, EU CRA |
| **Policy Evaluator** | Evaluate YAML policy rules against findings; produce PASS/FAIL/WARN per rule |
| **Misuse Detector** | Flag specific misuse patterns: ECB mode, static IV, weak PRNG, insufficient KDF iterations |
| **Certificate Analyser** | Parse and analyse embedded certificates; check expiry, signature algorithm, key size |

### 2.4 CBOM Store

Persistent storage for all CBOM data.

| Component | Responsibility |
|---|---|
| **Scan Records** | Metadata per scan: timestamp, repo, branch, commit SHA, scanner version, duration |
| **CBOM Documents** | Full CycloneDX 1.7 JSON per scan; immutable once written |
| **Asset Graph** | Graph model of component relationships — stored in PostgreSQL (Phase 1–2), migratable to Neo4j (Phase 3) via Graph Abstraction Layer |
| **Diff Engine** | Compare two CBOM snapshots; produce structured changelog |
| **Merge Engine** | Aggregate CBOMs from multiple services into a portfolio-level CBOM |

### 2.4.1 Database Architecture

| Store | Technology | What It Holds |
|---|---|---|
| **Primary DB** | PostgreSQL 17 | Scan records, findings, users, orgs, groups, projects, policies, audit logs, CBOM metadata |
| **Graph layer** | PostgreSQL CTEs (Phase 1–2) → Neo4j (Phase 3) | Asset dependency graph — nodes and edges |
| **Time-series** | TimescaleDB (PostgreSQL extension) | Crypto posture trends, compliance score history |
| **Cache / Queue** | Redis | Celery task queue, scan result cache, session store |
| **Object store** | PostgresCBOMStore (dev) → MinIO / S3-compatible (production) | CBOM JSON snapshots, PDF reports, attestation bundles |

**CBOM JSON is never stored as a Postgres column in production.** Postgres holds scan metadata and a pointer (object key) to the JSON stored in object storage. At 200k scans/day even 100KB average JSON is 20GB/day — object storage is the only viable option at scale.

#### CBOMStore Abstraction

All CBOM JSON reads and writes go through a `CBOMStore` interface — no business logic accesses storage directly:

```
CBOMStore (interface)
 ├── PostgresCBOMStore   ← Dev / early stage (JSON as BYTEA in Postgres)
 └── S3CBOMStore         ← Production (JSON in MinIO or any S3-compatible store)
```

Migration trigger: switch implementation when CBOM storage exceeds ~10GB or scan volume exceeds ~500/day. Migration is a one-time script — read from Postgres, write to MinIO, store object key, drop the column.

The same abstraction applies to PDF reports and signed attestation bundles.

### 2.4.2 Hot / Warm / Cold Storage Tiers

At enterprise scale (~20k repos, ~10 scans/day each = ~200k scans/day), data must be tiered to keep Postgres lean and storage costs manageable.

| Tier | Age | Postgres State | Object Storage Class | Query Behaviour |
|---|---|---|---|---|
| **Hot** | 0–90 days | Uncompressed TimescaleDB chunks; full indexes | S3 Standard | Full API — normal response times |
| **Warm** | 90 days–12 months | TimescaleDB compressed chunks (10–20× compression) | S3 Standard-IA | Available via API; slightly slower (decompress on read) |
| **Cold** | 12+ months | Exported; removed from Postgres | S3 Glacier | Archive retrieval only — async, minutes to hours |

**Default retention (all configurable by Org Admin):**

| Data Type | Default Retention | Cold Archive After |
|---|---|---|
| CBOM snapshots | 12 months | 12 months |
| Scan history / findings | 12 months | 12 months |
| Audit logs | 24 months | 24 months |

**Partition strategy:**

```
scan_records   — partitioned by month (TimescaleDB chunks)
findings       — partitioned by scan_date month
audit_logs     — partitioned by month; compressed after 90 days
graph_nodes    — partitioned by org_id + scan_id
```

**Automated tier transitions (Celery scheduled jobs):**
- Day 90: compress TimescaleDB chunks; transition object storage to Standard-IA
- Day 365: archive findings + scan records to Glacier; remove from Postgres
- Day 730: archive audit logs to Glacier; purge from Postgres

### 2.4.3 Graph Data Model (Migration-Ready)

The graph is modelled as explicit **nodes** and **edges** tables in PostgreSQL — not as nested relational joins. This maps directly to Neo4j nodes and relationships with no schema redesign when migrated.

**Node types:**

| Node Type | Represents |
|---|---|
| `service` | A repository or microservice |
| `library` | A crypto library (OpenSSL, BouncyCastle, ring, etc.) |
| `algorithm` | A crypto algorithm instance (AES-256-GCM, RSA-2048, etc.) |
| `key_material` | A key, IV, salt, or nonce |
| `certificate` | An X.509 certificate |
| `protocol` | A TLS/SSH/DTLS protocol configuration |

**Relationship types:**

| Relationship | Meaning |
|---|---|
| `USES` | service → library |
| `IMPLEMENTS` | library → algorithm |
| `CONFIGURED_WITH` | algorithm → key_material |
| `SECURED_BY` | service → certificate |
| `NEGOTIATES` | service → protocol |
| `DEPENDS_ON` | service → service (inter-service graph, Phase 3) |

**PostgreSQL schema (Phase 1–2):**

```sql
CREATE TABLE graph_nodes (
    id          UUID PRIMARY KEY,
    org_id      UUID NOT NULL,           -- tenant isolation
    node_type   VARCHAR(50) NOT NULL,    -- see node types above
    external_id VARCHAR(255) NOT NULL,   -- FK to the entity (finding_id, project_id, etc.)
    properties  JSONB,                   -- flexible per-type metadata
    scan_id     UUID,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE graph_edges (
    id                UUID PRIMARY KEY,
    org_id            UUID NOT NULL,     -- tenant isolation
    source_node_id    UUID REFERENCES graph_nodes(id),
    target_node_id    UUID REFERENCES graph_nodes(id),
    relationship_type VARCHAR(50) NOT NULL,
    properties        JSONB,
    scan_id           UUID,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX ON graph_nodes(org_id, node_type);
CREATE INDEX ON graph_edges(org_id, source_node_id);
CREATE INDEX ON graph_edges(org_id, target_node_id);
```

### 2.4.4 Graph Abstraction Layer (GAL)

All graph queries go through a single `GraphRepository` interface. No raw CTE queries exist outside this layer. This is what makes the Neo4j migration a drop-in swap rather than a codebase-wide refactor.

```
GraphRepository (interface)
 ├── PostgresGraphRepository   ← Phase 1–2 implementation (recursive CTEs)
 └── Neo4jGraphRepository      ← Phase 3 implementation (Cypher) — drop-in replacement
```

**Interface methods:**

| Method | Purpose |
|---|---|
| `upsert_node(type, external_id, properties)` | Create or update a node |
| `upsert_edge(source_id, target_id, relationship, properties)` | Create or update an edge |
| `get_node(node_id)` | Fetch a single node |
| `get_neighbors(node_id, direction, relationship_type)` | Direct neighbours |
| `traverse(start_node_id, max_depth, filters)` | Multi-hop traversal |
| `find_path(source_id, target_id)` | Shortest path between two nodes |
| `blast_radius(node_id)` | All nodes affected if this node is compromised |
| `delete_scan_graph(scan_id)` | Remove all nodes/edges from a specific scan |

### 2.4.5 Neo4j Migration Path (Phase 3)

When migrating from PostgreSQL CTEs to Neo4j:

```
Phase 3 Migration Steps:

1. Deploy Neo4j alongside PostgreSQL
2. Implement Neo4jGraphRepository behind the existing GAL interface
3. Enable dual-write mode:
     → All graph writes go to both PostgreSQL and Neo4j
     → All graph reads still served by PostgreSQL
4. Run parity validation — compare traversal results from both
5. Switch reads to Neo4j (single config flag)
6. Monitor for one release cycle
7. Disable PostgreSQL graph writes; drop graph_nodes / graph_edges tables
     (PostgreSQL itself stays — only the graph tables are removed)
```

**What does NOT change during migration:**
- PostgreSQL continues holding all non-graph data (CBOM docs, findings, users, etc.)
- API contracts are unchanged — GAL interface is identical
- Multi-tenant isolation: `org_id` filtering moves from SQL WHERE clauses to Cypher WHERE clauses — same logic, different syntax

### 2.5 Integration Layer

| Integration | Protocol |
|---|---|
| GitHub App | OAuth, Webhooks, Checks API, PR Review API |
| GitLab | OAuth, Webhooks, MR Notes API |
| Jenkins | Plugin (Java); post-build step |
| Jira / Linear | REST API; auto-create tickets on policy violation |
| Slack / Teams | Webhook; alert on new Critical findings |
| SonarQube | Plugin; additional security tab in SonarQube UI |
| Dependency-Track | REST API; push CBOM to Dependency-Track portfolio |
| Sigstore / Rekor | CBOM attestation and signing |

---

## 3. Scanning Pipeline (Per File)

```
Source file
    │
    ▼
1. Language detection
   (extension mapping + first-line content sniffing)
    │
    ▼
2. Preprocessor
   (strip comments for C/C++ macro expansion; normalise whitespace)
    │
    ├─▶ 3a. AST Parser (language-specific via tree-sitter)
    │        │
    │        ├─▶ 3b. Call graph builder
    │        │        └─▶ Inter-procedural taint engine
    │        │              (source → passthrough → sink)
    │        │
    │        └─▶ 3c. Constant resolver
    │                 └─▶ Inline literal values for algorithm parameters
    │
    ├─▶ 4.  Regex layer
    │        (PEM headers, key blobs, algorithm name strings,
    │         secret/credential patterns — fast, language-agnostic)
    │
    └─▶ 5.  Config file parser (if applicable)
             (TLS config, Java security props, k8s secrets,
              Dockerfiles, .env, openssl.cnf, nginx/httpd.conf)
    │
    ▼
6. Library API model lookup
   (map detected call signature → CBOM asset type + properties)
    │
    ▼
7. Confidence scoring
   (High / Medium / Low / Unresolved per finding)
    │
    ▼
8. CycloneDX component builder
   (populate cryptoProperties: algorithmProperties /
    protocolProperties / certificateProperties /
    relatedCryptoMaterialProperties)
    │
    ▼
9. Emit to CBOM document
```

---

## 4. Deployment Models

### 4.1 CLI Tool (All Tiers)

Single binary. No server required. Suitable for local development and CI/CD pipelines.

```bash
cbom scan ./myproject --output cbom.json --format cyclonedx-json
cbom scan ./myproject --policy ./policy.cbom.yml --fail-on CRITICAL
cbom scan https://github.com/org/repo --branch main
cbom diff cbom-before.json cbom-after.json
cbom report --input cbom.json --compliance nist-800-131a --format pdf
```

### 4.2 Self-Hosted Server (Enterprise)

Docker / Kubernetes deployment. REST API + Web UI. Full feature set including dashboard, portfolio management, RBAC, and nested group hierarchy (see [RBAC](09-rbac.md)).

```
┌──────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                  │
│                                                      │
│  ┌──────────┐  ┌───────────┐  ┌───────────────────┐ │
│  │  API     │  │  Scanner  │  │  Frontend (React) │ │
│  │  Server  │  │  Workers  │  │                   │ │
│  │ (Go/     │  │  (pool)   │  └───────────────────┘ │
│  │  FastAPI)│  └───────────┘                        │
│  └──────────┘        │                              │
│       │         ┌────▼──────────────┐               │
│       │         │  Redis (queue)    │               │
│       │         └───────────────────┘               │
│       │                                             │
│  ┌────▼───────────────────────────────────────────┐ │
│  │  PostgreSQL + TimescaleDB (CBOM store + trends)│ │
│  └────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Neo4j / pgvector (Asset dependency graph)      │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

### 4.3 SaaS (Multi-Tenant)

Hosted service with GitHub/GitLab App installation. Per-project and organisation-level billing.

### 4.4 SonarQube Plugin

Adds a CBOM tab to SonarQube's security dashboard. Surfaces crypto findings alongside existing SonarQube vulnerability findings.

### 4.5 API-Only

Full REST API with OpenAPI 3.1 specification. For organisations building their own integrations or portals.

---

## 5. Security Considerations for the Tool Itself

| Concern | Mitigation |
|---|---|
| Scanning untrusted code | Run scanner in sandboxed container (gVisor / Firecracker); no code execution |
| CBOM documents contain sensitive info (key material) | Sensitive material fields (`value`) omitted by default; require explicit `--include-values` flag |
| API authentication | JWT-based auth with short-lived tokens; API keys for CI/CD |
| CBOM integrity | All CBOM artifacts signed with Sigstore; stored with SHA-256 digest |
| Multi-tenant data isolation | Hard org boundaries at database level via PostgreSQL RLS; nested group hierarchy enforced at application layer |
| Source code access | Ephemeral clone in isolated temp directory; deleted immediately after scan |
