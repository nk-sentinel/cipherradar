# ADR-033: Remove Joern (Pass 3) from Detection Pipeline

**Status:** Accepted
**Date:** 2026-03-23
**Decision Makers:** Development team
**Supersedes:** ADR-011 (Joern Integration Model) — partially; Joern subprocess model no longer used

## Context

CipherRadar's detection engine was designed as a 3-pass pipeline (ADR-004):
1. **Pass 1:** tree-sitter AST analysis (constant propagation, direct API detection)
2. **Pass 2:** OpenGrep taint analysis (cross-statement dataflow)
3. **Pass 3:** Joern CPG analysis (inter-procedural, cross-function dataflow)

A benchmark comparison against IBM CBOMkit (v1.4.5) revealed that Pass 3 provides negligible value relative to its cost:

### Benchmark Evidence

| Metric | Pass 1 | Pass 1+2 | Pass 1+2+3 | CBOMkit |
|---|---|---|---|---|
| Components | 540 | 556 | DNF* | 163 |
| Scan time | 254ms | 759ms | >27 min* | 17,258ms |
| Tool size | 0 MB | 33 MB | 1,633 MB | 33 MB + SQ |

*DNF = Did Not Finish. Joern CPG export ran >27 minutes on a 50-file test project and was terminated.

### Why Joern Is No Longer Needed

All 5 Joern query scripts have equivalent OpenGrep taint rules:

| Joern Query | OpenGrep Equivalent | Status |
|---|---|---|
| `crypto-key-flow.sc` | `cbom-java-keygen-to-cipher` + `cbom-java-kdf-to-cipher-chain` | Covered |
| `hardcoded-secret-flow.sc` | `cbom-java-hardcoded-key-to-secretkeyspec` | Covered |
| `iv-reuse.sc` | `cbom-java-hardcoded-iv` | Covered |
| `cert-validation-bypass.sc` | `cbom-java-trust-all-certificates` | Covered |
| `deprecated-api-chain.sc` | CBOM inventory rules (38 new rules) | Covered |

Additionally, 16 Java scanner FN fixes and 38 CBOM inventory OpenGrep rules were added, further reducing the gap Pass 3 was meant to fill.

### Issues with Joern

1. **Performance:** >27 minutes for 50 files. Production codebases would take hours.
2. **Size:** 1.6 GB download (JVM-based, bundles all language frontends).
3. **JVM dependency:** Requires Java 17+ runtime.
4. **Version management:** The pinned version (v4.0.0) did not exist in GitHub releases.
5. **Maintenance burden:** Scala query scripts require Joern-specific expertise.
6. **Diminishing returns:** OpenGrep's taint analysis covers the same patterns at 19x speed.

## Decision

Remove Joern (Pass 3) from the active detection pipeline:

1. Remove `joern` from `cradar install-tools`
2. Change `--passes` default from `1,2,3` to `1,2`
3. Change `--deep` alias from `1,2,3` to `1,2`
4. Remove `runPass3()` from scan command
5. Remove Joern import from scan.go
6. Update pass validation to accept 1-2 only
7. Keep `cli/internal/joern/` package in codebase (archived, not imported)

The `joern/` package and query scripts are retained in the source tree for reference but are no longer imported or executed. They may be revisited if Joern's performance improves significantly or if a use case arises that OpenGrep cannot address.

## Consequences

### Positive
- `cradar install-tools` no longer downloads 1.6 GB
- No JVM dependency for standard installation
- `--passes 1,2` is the only mode, simplifying the pipeline
- Scan time remains under 2 seconds even for large projects

### Negative
- Loss of true inter-procedural analysis (cross-function dataflow)
- Some theoretical edge cases in deeply nested crypto wrapper chains may be missed
- `cradar-full` distribution no longer bundles Joern

### Neutral
- The `joern/` package remains in the codebase for future reference
- ADR-011 is superseded for the subprocess integration model, but Joern's architectural concept (CPG analysis) remains valid if performance improves

## Alternatives Considered

1. **Keep Joern but only for nightly scans:** Rejected — the >27 minute scan time makes even nightly use impractical for most projects.
2. **Replace Joern with CodeQL:** Rejected — CodeQL has similar JVM/build dependencies and violates ADR-003 (no build requirement).
3. **Invest in Joern performance tuning:** Rejected — the 1.6 GB size and JVM requirement are fundamental, not tunable.
