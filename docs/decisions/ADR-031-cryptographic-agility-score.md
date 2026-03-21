# ADR-031: Cryptographic Agility Score — 5-Factor Model

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

Enterprise security teams need a single metric to answer: "How easy would it be to migrate this project's cryptography?" This question arises in post-quantum migration planning, compliance audits, and security posture reviews. Individual CBOM findings are too granular — leadership needs a project-level score that tracks improvement over time.

Cryptographic agility — the ability to swap cryptographic algorithms with minimal code changes — depends on how the codebase uses cryptography: whether calls are centralised or scattered, whether abstraction layers exist, and whether the algorithms in use have known replacements.

---

## Decision

### 0–100 composite score per project

Each project receives a Cryptographic Agility Score from 0 (completely rigid — migration would require rewriting the entire codebase) to 100 (fully agile — algorithms can be swapped via configuration). The score is computed from 5 weighted factors:

### Factor 1: Call Site Concentration (20%)

Measures how many distinct locations in the codebase invoke cryptographic APIs.

| Metric | Score |
|---|---|
| All crypto calls in ≤ 3 files | 100 |
| 4–10 files | 75 |
| 11–25 files | 50 |
| 26–50 files | 25 |
| 50+ files | 0 |

**Rationale:** Fewer call sites mean fewer places to change during migration. Centralised crypto usage indicates architectural awareness.

### Factor 2: Abstraction Level (25%)

Measures whether the codebase uses wrapper/abstraction layers or calls crypto primitives directly.

| Metric | Score |
|---|---|
| All calls go through a project-defined wrapper (e.g. `CryptoService.encrypt()`) | 100 |
| Majority (>70%) through wrappers | 75 |
| Mixed — some wrappers, some direct | 50 |
| Majority direct API calls (e.g. `Cipher.getInstance("AES/CBC/PKCS5Padding")`) | 25 |
| All direct primitive calls | 0 |

**Rationale:** Abstraction layers are the primary enabler of cryptographic agility. Changing one wrapper implementation migrates all callers.

**Detection:** Identified by analysing the call graph — if multiple crypto API calls originate from the same intermediate function, that function is classified as a wrapper.

### Factor 3: Algorithm Diversity (15%)

Measures the number of unique cryptographic algorithms used in the project.

| Metric | Score |
|---|---|
| 1–2 unique algorithms | 100 |
| 3–5 unique algorithms | 75 |
| 6–10 unique algorithms | 50 |
| 11–20 unique algorithms | 25 |
| 20+ unique algorithms | 0 |

**Rationale:** Fewer distinct algorithms means fewer migration paths to plan and test. Projects using a single symmetric + single asymmetric + single hash are easier to migrate than projects using 15 different algorithms.

### Factor 4: Key Management Centralisation (20%)

Measures whether key material is managed through a centralised system or scattered throughout the codebase.

| Metric | Score |
|---|---|
| All keys via KMS/HSM/vault integration | 100 |
| Majority via KMS; some config-file keys | 75 |
| Keys in config files / environment variables | 50 |
| Some hardcoded keys alongside config keys | 25 |
| Hardcoded key material in source | 0 |

**Rationale:** Centralised key management means key rotation and algorithm migration can be coordinated from a single point. Hardcoded keys require code changes for every migration.

### Factor 5: Migration Readiness (20%)

Measures the percentage of findings that have a known post-quantum cryptography (PQC) replacement path.

| Metric | Score |
|---|---|
| 100% of algorithms have known PQC replacement | 100 |
| 75–99% | 75 |
| 50–74% | 50 |
| 25–49% | 25 |
| < 25% | 0 |

**Rationale:** Even a well-architected codebase scores poorly on agility if it uses algorithms with no known migration path (e.g. custom or obscure constructions).

### Composite formula

```
Agility Score = (0.20 × CallSiteConcentration)
              + (0.25 × AbstractionLevel)
              + (0.15 × AlgorithmDiversity)
              + (0.20 × KeyManagementCentralisation)
              + (0.20 × MigrationReadiness)
```

### Display tiers

| Score Range | Label | Color |
|---|---|---|
| 80–100 | Highly Agile | Green |
| 60–79 | Moderately Agile | Yellow |
| 40–59 | Limited Agility | Orange |
| 0–39 | Rigid | Red |

### Tracking

The score is computed after every scan and stored in `scan_metrics` (TimescaleDB hypertable per ADR-012). This enables time-series trending: "Our agility score improved from 35 to 62 over Q3 as we centralised crypto calls."

---

## Options Considered

### Option A: Binary score (agile / not agile) (rejected)
A simple yes/no classification. Rejected because it provides no gradient for improvement tracking and no actionable guidance on which dimension to improve.

### Option B: 3-factor model (rejected)
A simpler model using only concentration, abstraction, and migration readiness. Rejected because algorithm diversity and key management are independently actionable dimensions that security teams need to track separately.

### Option C: Machine-learned score (rejected)
Train a model on known-agile vs known-rigid codebases. Rejected because the training data does not exist in sufficient quantity, the model would be opaque to auditors, and the 5-factor model is transparent and auditable — each factor can be independently verified and challenged.

---

## Consequences

- **Positive:** Single metric enables executive-level reporting on migration readiness
- **Positive:** Per-factor breakdown provides actionable guidance (e.g. "improve abstraction level")
- **Positive:** Time-series tracking shows improvement trends
- **Positive:** Transparent formula — auditors can verify each factor independently
- **Negative:** Threshold values (e.g. "4–10 files = 75") are heuristic — may need tuning based on real-world data
- **Negative:** Abstraction level detection requires call graph analysis (Pass 3 / Joern) — not available in Pass 1-only scans
- **Negative:** Score comparison across projects of different sizes may be misleading without normalisation context

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/02-architecture.md` | Agility Score computation component added to backend architecture |
| `docs/07-tech-stack.md` | No new tech — computed from existing CBOM data |
| `docs/06-compliance.md` | Agility Score referenced in compliance reporting section |
| `frontend/` | Dashboard: project-level score widget, trend chart, per-factor breakdown |
