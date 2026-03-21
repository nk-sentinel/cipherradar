# ADR-010: CLI Distribution Model, Tool Bundling, and Shared Asset Embedding

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-18 |
| **Deciders** | Architecture session |

---

## Context

Three related decisions about how the CLI binary is distributed and how shared data assets are managed across the CLI and backend:

1. **Go module path** — what internal identifier to use for the Go module
2. **OpenGrep/Joern distribution** — how third-party analysis tools reach the end user, given that some environments are air-gapped or behind firewalls where direct downloads are not allowed
3. **Quantum algorithm table** — where the algorithm → quantum status mapping lives and how it is accessed at runtime by both the CLI and backend

---

## Decisions

### 1. Go Module Path

**`github.com/nk-sentinel/cipherradar/cli`**

### 2. CLI Distribution — Two Flavors

Two binary variants published to GitHub Releases on every release:

| Variant | Contents | Size | Use Case |
|---|---|---|---|
| **`cbom`** | CLI binary only | ~15 MB | Developers with internet access; CI/CD with direct download |
| **`cbom-full`** | CLI + OpenGrep + Joern + YARA-X pre-bundled | ~300 MB | Air-gapped environments; behind-firewall enterprise; fully self-contained |

For users of the lightweight `cbom` binary who have internet access, a `cbom install-tools` subcommand downloads OpenGrep, Joern, and YARA-X from their official GitHub Releases, verifies checksums, and caches them to `~/.cbom/tools/` (or `$CBOM_TOOLS_DIR`).

Pass behaviour when tools are not available:
- Pass 1 (tree-sitter) — always runs, no external tools required
- Pass 2 (OpenGrep) — skipped gracefully if not found; CLI prints: `Pass 2 skipped — run 'cbom install-tools' or use cbom-full`
- Pass 3 (Joern) — skipped gracefully if not found; same message

### 3. Shared Asset Embedding

Shared data assets (quantum algorithm table, library API models, Semgrep rule manifests) live in `scanner/library-models/` in the repository as the single source of truth.

At build time, these assets are **embedded into the CLI binary and bundled into the backend Python package** — they are not fetched or read from the filesystem at runtime:

| Component | Embedding mechanism |
|---|---|
| CLI (Go) | `//go:embed` directive — assets compiled into binary |
| Backend (Python) | `importlib.resources` — assets bundled as package data in `pyproject.toml` |

This means:
- A specific CLI version always uses the same table as the corresponding backend version (they were built from the same source commit)
- Works fully in air-gapped environments — no external fetch at runtime
- When NIST updates PQC standards, the table is updated in `scanner/library-models/`, and a new release is cut — old versions retain their bundled table

---

## Rationale

### Go module path
The CLI is a binary, not a library. No external project imports its packages. A vanity domain (`go.cipherradar.io/cli`) adds infrastructure overhead (domain ownership, redirect server, `go-import` meta tags) for zero user-facing benefit. The GitHub path mirrors where the code lives and is universally understood.

### Two distribution flavors
A single lightweight binary preserves the zero-friction install experience for the majority of users. A full bundle solves the air-gapped enterprise problem without forcing all users to carry the weight of bundled tools. GoReleaser supports multiple artifact configurations natively — build cost is minimal.

The `cbom install-tools` command covers the middle case: internet-accessible environments that still want a small initial download.

### Shared asset embedding
Loading assets from the filesystem at runtime creates deployment complexity (where is the file? is it the right version?), breaks in air-gapped environments, and risks CLI/backend version mismatch. Embedding at build time eliminates all three problems. `//go:embed` is a standard Go feature with zero runtime overhead beyond the initial binary size. The source file in `scanner/library-models/` remains the single place to make edits.

---

## Consequences

- **Positive:** Air-gapped deployments fully supported with `cbom-full`
- **Positive:** Lightweight `cbom` binary remains fast to download and install
- **Positive:** CLI and backend always ship with matching data — no version drift
- **Positive:** No runtime file dependency — embedded assets always available
- **Negative:** `cbom-full` archive is large (~300 MB with OpenGrep + Joern + YARA-X) — acceptable for enterprise use case
- **Negative:** Updating the quantum table or library models requires a new release — cannot hot-patch

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | CLI section: add two-flavor distribution; embed mechanism noted |
| `CLAUDE.md` | Module path documented; note on `//go:embed` for shared assets |
