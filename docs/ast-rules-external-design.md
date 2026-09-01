# External AST (Pass-1) Rules — Design (issue #114, Phase A)

**Status:** ✅ Implemented — shipped in **v0.5.0-rc.1**. Phase A (Java, #118) and Phase B (the remaining 11 languages, #119–#120) are both complete; `--ast-rules-dir` (and `CRADAR_AST_RULES_DIR`) replace the embedded Pass-1 tables per language, with embedded fallback verified to reproduce detection byte-for-byte on the corpus. This document is retained as the design record.
**Goal:** Let operators supply Pass-1 (tree-sitter AST) crypto-detection *data* externally, with the same replace-semantics Pass 2 (`--rules-dir`) and Pass 3 (`--yara-rules-dir`) already have — so a downstream portal (gauntlet) can serve **all** cradar rules, not just Passes 2–3.

---

## 1. What "a Pass-1 rule" actually is

Pass-1 detection has two separable halves:

| Half | Example | Externalize? |
|---|---|---|
| **Machinery** — tree-sitter queries that locate syntactic sites | "find `X.getInstance("...")` calls", "find `new SecretKeySpec(...)`" | **No** (Phase A). Stable Go code; queries are not what a portal curates. |
| **Data** — tables mapping the located token → crypto semantics | `algorithmFamilyMap["AES"]="aes"`, `jcaClassInfo["Cipher"]={primitive:"block-cipher"}` | **Yes.** These are the ~90 hardcoded Go maps across 12 languages. |

The **data tables** are what get externalized. This mirrors the existing in-tree precedent: `cli/internal/scanner/quantum/quantum-readiness.yml` is an embedded YAML data table the Go machinery consumes (`quantum.go` `//go:embed` + `init()`).

**Replace-semantics requirement.** For `--ast-rules-dir` to mean "use *only* these rules" (per the requested Pass-2 parity), **all** of a language's data tables must be externalized. Partial externalization would make the flag additive, not replace. Hence the phased rollout (§6): a language is "done" only when every one of its tables loads from data.

---

## 2. The Java tables (the Phase-A target)

`cli/internal/scanner/java/java_scanner.go` has 7 package-level maps, consumed at fixed call sites:

| Go table | Shape | Consumed at | YAML section |
|---|---|---|---|
| `jcaClassInfo` | class → `{primitive, ruleTag}` | `:232` | `jca_classes` |
| `algorithmFamilyMap` | algo name → family | `lookupAlgoFamily` | `algorithm_families` |
| `bcEngineAlgorithms` | BC engine class → `{...}` | `:1xxx` | `bc_engines` |
| `bcAsymmetricAlgorithms` | BC class → `{...}` | | `bc_asymmetric` |
| `bcModes` | BC mode class → mode | | `bc_modes` |
| `bcDigestAlgorithms` | BC digest class → `{...}` | `:1140` | `bc_digests` |
| `sslProtocols` | protocol string → `{...}` | `:1222` | `ssl_protocols` |

## 3. Proposed file format

One YAML file per language, named `<lang>.yml` (e.g. `java.yml`), living in an embedded `data/` dir (default) and loadable from `--ast-rules-dir` (override). Top-level keys are the **table sections** above; each entry is a typed row. Example (abridged, real Java values):

```yaml
version: 1
language: java

jca_classes:
  - class: Cipher
    primitive: block-cipher
    rule_tag: cipher
  - class: MessageDigest
    primitive: hash
    rule_tag: digest

algorithm_families:
  - name: AES
    family: aes
  - name: DESEDE
    family: 3des
  - { name: SHA-256, family: sha-256 }

ssl_protocols:
  - protocol: TLSv1.1
    # ...typed fields mirroring the Go struct
```

Design choices:
- **Sectioned, typed rows** (not free-form) so a loader can validate each row against the Go struct it feeds, and so a malformed row fails loudly (Pass-2 parity: "error if no loadable rules / rules with issues").
- **`version` + `language`** headers for forward-compat and cross-checking the dir against the target language.
- **YAML** (not JSON) to match `quantum-readiness.yml` and `gopkg.in/yaml.v3` already in the tree.

## 4. Loader + precedence

New package `cli/internal/scanner/astrules`:
- `//go:embed data/*.yml` holds the built-in tables (source of truth stays `scanner/ast-rules/*.yml`, synced via `go generate`, exactly like OpenGrep/YARA rules).
- `Load(lang, dir string) (*Tables, error)`:
  - `dir == ""` → parse the embedded `<lang>.yml`.
  - `dir != ""` → parse `<dir>/<lang>.yml`; **error** if absent/empty/malformed (replace-semantics + Pass-2-style validation).
- Precedence: `--ast-rules-dir` flag > `CRADAR_AST_RULES_DIR` env > embedded.
- Each language scanner's `New()` takes the loaded `*Tables` (or fetches via a shared accessor) instead of referencing package-level `var` maps.

## 5. Wiring (mirrors the just-landed --yara-rules-dir)

- Flag `--ast-rules-dir` in `scan.go` (beside `--rules-dir` / `--yara-rules-dir`).
- Resolve + validate up front when explicitly set; thread the dir into `scannerinit.DefaultRegistryWithOptions` (the single builder added for `--yara-rules-dir`) via a new `AstRulesDir` option; the language `New()`s receive their `*Tables`.
- `astrules.ValidateRulesDir(dir, langs)` mirrors `yarax.ValidateRulesDir`.

## 6. Rollout — ✅ complete (v0.5.0-rc.1)

- **Phase A (#118):** ✅ defined the format + loader + flag; converted **Java** end-to-end (all 7 tables → `java.yml`), embedded-default reproducing current detections byte-for-byte, `--ast-rules-dir` replacing them. Regression-gated against the corpus (`~/projects/CipherRadarTestProj`) and the Java scanner tests.
- **Phase B (#119–#120):** ✅ converted the remaining 11 languages table-by-table to the same format. Each language flipped from Go-map to data-loaded with a per-language regression check. External rule files ship under `scanner/ast-rules/<lang>.yml` (embedded copies at `cli/internal/scanner/astrules/data/`).

## 7. Verification (Phase A)

- Java scanner unit tests + corpus scan produce **identical** findings with the embedded tables (proves the conversion is behavior-preserving).
- `--ast-rules-dir <dir-with-modified-java.yml>` changes detection accordingly; empty/absent/malformed dir → exit 4.
- `go test ./internal/scanner/java/... ./internal/scanner/astrules/... ./internal/cmd/...`.

## 8. Decisions (resolved 2026-08-31)

1. **Scope of "replace":** `--ast-rules-dir` replaces **only the data tables**; the tree-sitter query machinery stays in Go. Externalizing query shapes (`.scm`) is a separate future follow-up, out of scope.
2. **File layout:** **one file per language** (`java.yml`, `python.yml`, …).
3. **Partial dirs:** **per-language fallback** — a dir replaces only the languages whose `<lang>.yml` it contains; undefined languages keep the embedded tables. A `--ast-rules-dir` that contains **no** recognized `<lang>.yml` at all is an error (Pass-2 "no loadable rules" parity); a present-but-malformed `<lang>.yml` is an error.
