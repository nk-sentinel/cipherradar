# ADR-034: Finding Identity & Cross-Scan Matching

**Status:** Accepted
**Date:** 2026-03-26
**Decision Makers:** Development team
**Phase:** 4.5 (prerequisite for D14 finding status model)

## Context

CipherRadar scans the same codebase repeatedly. Each scan produces findings that need to be correlated with findings from previous scans so that:

- Status carries over (FP/Risk Accepted findings stay marked — D14)
- FP/RA request decisions persist (D15)
- MTTR is calculated accurately (D14)
- Audit trails track the lifecycle of a single finding, not phantom duplicates (D28)
- Rule effectiveness analytics reflect real signal, not churn (D16)

Line numbers shift with every code change. Naively matching on `rule_id + file + line` would cause:
- Every refactor creates "new" findings and resolves old ones
- FP/RA markings lost
- MTTR reset to zero
- Audit trail polluted with false open/resolve cycles

## Decision

### Finding Identity Key

A finding is uniquely identified by:

```
finding_fingerprint = hash(rule_id + file_path + normalized_code_signature)
```

| Component | Description |
|---|---|
| `rule_id` | Detection rule that produced the finding (e.g., `cbom-java-weak-rsa`) |
| `file_path` | Relative path from project root |
| `normalized_code_signature` | Content-based fingerprint of the matched code (see below) |

Line number is stored as metadata for display but is **not** part of the identity.

### Normalized Code Signature

Before hashing, the matched code snippet is normalized:

1. Strip leading/trailing whitespace per line
2. Collapse consecutive whitespace to single space
3. Remove comments (language-aware, reuse tree-sitter parse)
4. Normalize string literals to placeholder (`"..."` → `"_STR_"`)
5. Normalize numeric literals to placeholder (`128` → `_NUM_`)
6. Preserve: function/method names, API calls, type names, operators

The normalized form captures the **structure** of the crypto usage, not the formatting or literal values.

Example — these produce the same signature:
```java
// Before
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

// After variable rename + formatting
Cipher  aesCipher =
    Cipher.getInstance( "AES/ECB/PKCS5Padding" );
```

Both normalize to: `Cipher _VAR_ = Cipher.getInstance(_STR_);`

### Cross-Scan Matching Algorithm

On each new scan:

1. Compute `finding_fingerprint` for every detected finding
2. Query existing findings for this project by `rule_id + file_path`
3. Match by fingerprint:

| Scenario | Action |
|---|---|
| Fingerprint matches existing finding | Same finding — update line number, keep status |
| Fingerprint matches but file_path changed | Check git rename detection (see below) |
| No fingerprint match, new finding | Create with status = Open |
| Existing finding not in new scan results | Status-dependent (see below) |

### Unmatched Existing Findings

| Current Status | New Scan Doesn't Detect It | Action |
|---|---|---|
| Open / In Review / In Progress | Not found | → Resolved (resolved_by: scan) |
| Risk Accepted | Not found | No change — stays RA |
| False Positive | Not found | No change — stays FP |
| Resolved | Not found | No change |

### File Rename Detection

When a file is renamed/moved between scans:

1. Run `git diff --find-renames` between the two scan commit SHAs (D21 provenance)
2. Build old_path → new_path mapping
3. Before creating "new" findings in renamed files, check if fingerprint matches an existing finding from the old path
4. If match: update `file_path`, preserve status and history

Fallback when git history unavailable (e.g., artifact/container scans): no rename detection, treated as new file.

### Fuzzy Matching (Degraded Mode)

When exact normalized fingerprint doesn't match but `rule_id + file_path` does:

1. Compute similarity between normalized signatures (Levenshtein ratio)
2. If similarity > 80%: treat as same finding, update fingerprint
3. If similarity ≤ 80%: new finding (old one follows unmatched rules above)

This handles cases where the crypto usage was slightly modified (e.g., algorithm parameter changed from AES-128 to AES-256) — the finding is "the same concern" even though the code changed.

### Duplicate Detection (Same File)

Same rule can fire multiple times in one file. Each occurrence has a unique fingerprint because the code context differs. If two findings in the same file have the same `rule_id`, they're distinguished by their `normalized_code_signature`.

## Data Model

```sql
ALTER TABLE findings ADD COLUMN fingerprint VARCHAR(64) NOT NULL;
ALTER TABLE findings ADD COLUMN normalized_signature TEXT;
CREATE INDEX idx_findings_fingerprint ON findings(project_id, fingerprint);
CREATE INDEX idx_findings_rule_file ON findings(project_id, rule_id, file_path);
```

- `fingerprint`: SHA-256 of the normalized identity key (indexed for fast lookup)
- `normalized_signature`: stored for debugging and fuzzy matching (not indexed)

## Consequences

### Positive
- FP/RA markings survive code refactors, formatting changes, line shifts
- MTTR reflects real fix time, not scan-to-scan churn
- Audit trail tracks true finding lifecycle
- Rule effectiveness metrics (D16) reflect actual signal-to-noise

### Negative
- Normalization logic is language-aware — needs per-language rules (reuses tree-sitter, already available)
- Fuzzy matching adds complexity; 80% threshold may need tuning per language
- Git rename detection adds a subprocess call; skipped when git unavailable

### Risks
- Over-aggressive normalization could merge distinct findings (mitigated: preserve API calls and type names)
- Under-aggressive normalization could split findings (mitigated: fuzzy fallback)
- Large files with many similar patterns could have fingerprint collisions (mitigated: include enough surrounding context)

## Alternatives Considered

| Alternative | Why Rejected |
|---|---|
| Line-number matching | Breaks on any code edit — unacceptable churn |
| Function-scope matching (rule_id + file + function_name) | Doesn't handle multiple findings in same function |
| Exact code matching (no normalization) | Formatting changes create phantom findings |
| Content-addressable (hash entire matched block) | Too brittle — any character change breaks match |

## References

| Document | Relationship |
|---|---|
| D14 (Finding Status Model) | Depends on stable finding identity for status persistence |
| D15 (FP/RA Request Workflow) | Depends on finding identity for decision persistence |
| D16 (Rule Effectiveness) | Depends on accurate finding lifecycle for FP rate calculation |
| D21 (Scan Provenance) | Provides commit SHAs needed for git rename detection |
| D28 (Audit Log) | Finding history integrity depends on consistent identity |
| `cli/internal/scanner/` | Implementation location for fingerprint computation |
| `backend/app/services/scan_matcher.py` | Implementation location for cross-scan correlation |
