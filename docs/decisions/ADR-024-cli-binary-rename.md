# ADR-024: CLI Binary Rename — cbom → cradar

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-20 |
| **Deciders** | Architecture session |

---

## Context

The CLI binary is currently named `cbom` (Cryptographic Bill of Materials). This name implies it only generates CBOMs, but CipherRadar's CLI now does significantly more:

- **Scanning** — 12 languages, 3 detection passes (tree-sitter, OpenGrep, Joern)
- **Policy enforcement** — YAML-based policy engine with CI/CD exit codes
- **CBOM diffing** — side-by-side snapshot comparison
- **Report generation** — CycloneDX JSON, SARIF, text, PDF
- **Compliance checking** — NIST, FIPS, PCI-DSS, CNSA 2.0, ISO 27001, EU CRA
- **Portal push** — uploading scan results to the CipherRadar portal (ADR-025)

The binary name should reflect the full product: CipherRadar.

---

## Decision

Rename the CLI binary from `cbom` to `cradar`.

### Changes Required

| Area | Before | After |
|---|---|---|
| Binary name | `cbom` | `cradar` |
| GoReleaser artifacts | `cbom` / `cbom-full` | `cradar` / `cradar-full` |
| Commands | `cbom scan`, `cbom diff`, etc. | `cradar scan`, `cradar diff`, `cradar policy check`, `cradar report`, `cradar install-tools`, `cradar version` |
| GitHub Actions | `cbom-action` | `cradar-action` |
| Config file | `.cbom.yml` | `.cradar.yml` |
| Tools directory | `~/.cbom/tools/` | `~/.cradar/tools/` |
| Environment variables | `CBOM_*` | `CRADAR_*` |

### Backward Compatibility

`cbom` is retained as a **legacy alias** (symlink) for backward compatibility during Phase 3. This gives existing CI/CD pipelines time to migrate. The alias will be removed in Phase 4 or later, with deprecation warnings printed when invoked via the old name.

### Unchanged

- Go module path remains `github.com/nk-sentinel/cipherradar/cli` (module path is an internal identifier, not user-facing)
- CycloneDX output format is unaffected
- All scanner logic, detection passes, and CBOM schema are unchanged

---

## Rationale

"CBOM" is a standard term (Cryptography Bill of Materials) and also the name of competing tools (CBOMkit). Using it as the binary name:
1. Implies the tool only generates CBOMs, underselling its scanning, policy, and compliance capabilities
2. Creates brand confusion with other CBOM tools
3. Does not connect the CLI to the CipherRadar product name

"cradar" is short, memorable, and unambiguous. It is the natural abbreviation of CipherRadar, following the pattern of other security tools (e.g., `grype`, `cosign`, `trivy`).

---

## Consequences

- **Positive:** Name reflects full product capability — scanning, policy, compliance, reporting, portal push
- **Positive:** Brand consistency with the CipherRadar product name
- **Negative:** Breaking change for existing CI/CD configurations that reference `cbom` (mitigated by legacy alias/symlink)
- **Negative:** All documentation, CI templates, GitHub Actions, and GitLab CI files must be updated

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `CLAUDE.md` | All `cbom` command references → `cradar`; note about legacy alias |
| `README.md` | Quick Start section updated; all command examples |
| `docs/08-roadmap.md` | CLI command examples; binary flavor names |
| `docs/13-phase3-implementation-plan.md` | A-M2 work description |
| `deploy/README.md` | All CI/CD examples; binary names; action references |
| `deploy/github-action/action.yml` | Binary build step; scan commands |
| `deploy/github-action/release.yml` | Artifact names; build output paths |
| `deploy/github-action/example-workflow.yml` | Workflow example |
| `deploy/gitlab-ci/cbom-scan.gitlab-ci.yml` | Renamed to `cradar-scan.gitlab-ci.yml`; all variable names and commands |
