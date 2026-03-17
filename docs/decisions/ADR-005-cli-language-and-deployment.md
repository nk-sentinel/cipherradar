# ADR-005: CLI Language and Deployment Model

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-15 |
| **Deciders** | Architecture session |

---

## Context

The CLI tool is the primary interface for developers and CI/CD pipelines. The choice of implementation language and packaging directly affects:
- Distribution friction (how hard is it to install?)
- Performance (how fast does a scan run?)
- Cross-platform support (macOS, Linux, Windows)
- Developer experience

## Decision

**Go** for the CLI tool, distributed as a single static binary via GoReleaser.

**Python (FastAPI)** for the backend API server and analysis/reporting layer.

## Rationale

### Go for CLI

| Property | Why It Matters |
|---|---|
| Single static binary | `curl .../cbom_linux_amd64 -o cbom && chmod +x cbom` — zero dependencies |
| Cross-platform compilation | `GOOS=darwin GOARCH=arm64 go build` — one command for all platforms |
| Performance | Parallel file scanning via goroutines; scanning 100k LOC in < 5 minutes |
| Startup time | Milliseconds — important for pre-commit hooks |
| Memory safety | No GC pauses during long scans; predictable memory usage |
| go-tree-sitter | Official tree-sitter Go bindings — first-class support |

Alternatives rejected:
- **Python**: Slow startup (~500ms); requires Python interpreter + venv; packaging (PyInstaller) produces large binaries with issues
- **Rust**: Excellent performance but slower development velocity; smaller team hiring pool
- **Node.js**: Large runtime; slow startup; not suitable for a security tool that should be auditable

### Python for Backend

The backend is data transformation and report generation — tasks where Python's ecosystem (pandas for data, ReportLab for PDF, FastAPI for async API) is the most productive choice. Performance here is less critical than in the CLI.

## Deployment Models Supported

| Model | Target | Description |
|---|---|---|
| CLI binary | Individual developers, CI/CD | Single binary; `cbom scan ./path` |
| Self-hosted server | Enterprise (data residency) | Docker / Kubernetes |
| SaaS | SME teams | Multi-tenant hosted service |
| SonarQube plugin | Existing SonarQube users | Adds CBOM tab to SonarQube UI |
| API-only | Custom integrations | Full REST API + OpenAPI 3.1 spec |

## Consequences

- Positive: CLI distributable without any runtime dependencies
- Positive: GoReleaser handles cross-platform builds, checksums, GitHub Releases, Homebrew tap automatically
- Positive: Go + Python split allows the right tool for each layer
- Negative: Two languages in one project — developers need to be comfortable with both
- Mitigation: The CLI (Go) and backend (Python) communicate only via the REST API — teams can work independently

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | Go and Python stacks detailed in full; GoReleaser, FastAPI listed |
| `docs/02-architecture.md` | Deployment models section lists CLI, self-hosted, SaaS, SonarQube plugin, API-only |
| `docs/08-roadmap.md` | Phase 1 deliverable: single Go binary; Phase 2: REST API + basic dashboard |
