# ADR-043: External Pass-1 (AST) detection rules

**Status:** Accepted (2026-09-01)

## Context

`cradar` detects crypto in three passes (ADR-004). Their rule sources had grown
asymmetric:

- **Pass 2 (OpenGrep taint):** already externally definable via `--rules-dir`
  (and `CRADAR_RULES_DIR`), with replace semantics — a supplied dir is used
  *instead of* the embedded rules, with validation ("error if no loadable rules").
- **Pass 3 (YARA-X):** rules were embedded only; no external override.
- **Pass 1 (tree-sitter AST):** detection lived in **~90 hardcoded Go maps across
  12 languages** — `algorithmFamilyMap`, `jcaClassInfo`, etc. — not externally
  definable at all.

A downstream portal (gauntlet, ADR-025) wants to serve **all** of cradar's
detection rules centrally so operators can curate them, not just Pass 2's. That
requires Pass 1 and Pass 3 to gain the same external-rules capability Pass 2 has
(gh #114).

## Decision

**Externalize the *data* half of Pass-1 detection as per-language YAML, embedded
by default and overridable — with the exact replace-semantics of `--rules-dir`.**

1. **Split machinery from data.** Pass-1 detection has two halves: *machinery*
   (tree-sitter queries that locate syntactic sites — stable Go code, not what a
   portal curates) and *data* (tables mapping a located token → crypto
   semantics). Only the **data tables** are externalized. This mirrors the
   in-tree precedent (`scanner/quantum/quantum-readiness.yml` is an embedded YAML
   table the Go machinery consumes).
2. **One data file per language** (`<lang>.yml`), embedded via `//go:embed`
   (`cli/internal/scanner/astrules/data/`, sourced from `scanner/ast-rules/`) as
   the default, so a vanilla scan needs no rule plumbing.
3. **`--ast-rules-dir` (and `CRADAR_AST_RULES_DIR`) override with per-language
   replace semantics.** A supplied dir replaces the embedded tables **for the
   languages whose `<lang>.yml` it contains**; languages it omits keep their
   embedded tables. An explicitly-provided dir with **no** recognized `<lang>.yml`,
   or a malformed file, is an error (Pass-2 "no loadable rules" parity).
4. **Pass 3 gets the parallel `--yara-rules-dir`** (and `CRADAR_YARA_RULES_DIR`),
   same replace-or-embedded contract.

After this, **every pass** supports external rules: `--rules-dir` (2),
`--ast-rules-dir` (1), `--yara-rules-dir` (3).

## Rejected alternatives

- **Externalize the tree-sitter queries too.** Rejected (for now): queries are
  detection *code*, not portal-curated data; their shape is coupled to grammar
  versions and would be unstable as an external contract. The machinery stays in
  Go; only the semantic tables are externalized.
- **Additive (merge) semantics** — treat `--ast-rules-dir` as *extra* rules on
  top of embedded. Rejected: breaks the "use *only* these rules" contract that
  Pass-2 parity requires and that a central portal needs to fully control output.
- **One combined rules file for all languages.** Rejected: couples unrelated
  languages, makes per-language serving/fallback awkward, and bloats every
  override.

## Consequences

- A central portal can serve the complete cradar rule set across all three
  passes; embedded defaults preserve zero-config operation and offline use.
- Per-language fallback means a partial `--ast-rules-dir` is safe (it only
  replaces what it defines).
- The ~90 Go maps become data files under `scanner/ast-rules/<lang>.yml`
  (+ embedded copies). Rollout was Phase A (Java, #118) then Phase B (the
  remaining 11 languages, #119–#120); embedded fallback was regression-gated to
  reproduce prior detection byte-for-byte on the corpus.
- Design record: `docs/ast-rules-external-design.md`.
- Shipped in **v0.5.0-rc.1** (gh #114).

## Related

ADR-004 (3-pass detection), ADR-009 (OpenGrep / `--rules-dir` for Pass 2),
ADR-039 (YARA-X Pass 3), ADR-035 (rule lifecycle & deprecation),
ADR-010 (asset embedding via `//go:embed`), ADR-025 (CLI-to-portal push).
