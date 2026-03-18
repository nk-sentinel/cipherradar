# Phase 1 — Implementation Plan

> **Document version:** v2
> **Last updated:** 2026-03-18
> **Status:** Active

---

## Change History

| Version | Date | Change |
|---|---|---|
| v1 | 2026-03-18 | Initial plan — orchestrator + subagent model, all 6 milestones |
| v2 | 2026-03-18 | All agents use Opus / High — no model mixing |

---

## Overview

Phase 1 is implemented using an **orchestrator + subagent model**:

- **Orchestrator** — strictly coordinates. Assigns subagents in dependency order, merges integration points (scanner registry, output format registration), and runs all quality/security validation skills after each subagent completes. Never writes implementation code.
- **Subagents** — each owns a single concern. Runs its own skills during implementation. Reports back to the orchestrator when done.

All commits are gated through the `/commit` skill (lint → sec-review → dep-audit → commit). No code is merged without passing the orchestrator's milestone-close gate.

---

## Model Configuration

All agents use the same model and effort level — no mixing.

| Setting | Value |
|---|---|
| **Model** | Opus 4.6 (1M context) |
| **Effort** | High |
| **Applies to** | Orchestrator + all subagents |

**Rationale:** Max 20x plan provides sufficient tokens. Opus everywhere ensures best code quality on first pass, reduces fix-and-retry loops, and produces better spec adherence (CycloneDX 1.7, SARIF 2.1). The cost of retrying Sonnet mistakes exceeds the cost of using Opus from the start.

---

## Skills Reference

| Skill | Category | Purpose |
|---|---|---|
| `/adr` | Architecture | Create a new ADR + update decision log |
| `/lint` | Quality | `go vet` + `golangci-lint` (Go); `ruff` (Python) |
| `/test-coverage` | Quality | Run tests with coverage; enforce per-package thresholds |
| `/sec-review` | Security | `gosec` + `govulncheck` (Go); `bandit` (Python) |
| `/dep-audit` | Security | `govulncheck` (Go); `pip-audit` (Python) |
| `/fuzz` | Security | Go fuzz tests on scanner inputs — must not panic or hang |
| `/commit` | Workflow | Gates lint + sec-review + dep-audit before every commit |
| `/benchmark` | Performance | Validate 100k LOC Java < 5 min; report throughput |
| `/profile` | Performance | CPU + memory `pprof` when benchmark targets are missed |
| `/build-cross` | Cross-platform | Build for macOS/Linux/Windows all targets; verify each binary |
| `/new-scanner` | Scaffolding | Scaffold new language scanner (struct, tests, fixtures, rules stub) |
| `/new-opengrep-rule` | Scaffolding | Scaffold OpenGrep YAML taint rule with correct structure |

**Hook:** `go vet` runs automatically after every `.go` file write/edit via PostToolUse hook.

---

## Implementation Plan

| Milestone | Agent | Depends On | Parallel? | Work | Skills |
|---|---|---|---|---|---|
| **M1** | Agent-Foundation | — | No | `go mod init`, deps (Cobra, Koanf v2, cyclonedx-go), `main.go`, `cmd/root.go`, all command stubs + flags | `/lint`, `/sec-review` |
| **M1** | Agent-Types | Agent-Foundation | No | `cli/internal/types/` — Finding, Asset, Location, Severity, QuantumStatus | `/lint`, `/test-coverage` |
| **M1** | Agent-CycloneDX17 | Agent-Types | Yes | `cli/internal/cyclonedx17/` — all 1.7 cryptoProperties structs + enums (~420 lines) | `/lint`, `/sec-review`, `/test-coverage` |
| **M1** | Agent-Output | Agent-Types | Yes | `cli/internal/output/` — writer interface + stubs (CycloneDX JSON, SARIF, text, PDF) | `/lint`, `/test-coverage` |
| **M1** | **Orchestrator gate** | All M1 agents | — | Merge, integrate, validate full build | `/lint`, `/sec-review`, `/test-coverage`, `/build-cross` |
| **M2** | Agent-TreeSitter | M1 complete | No | tree-sitter cgo integration, language detection, file dispatch, grammar loading | `/lint`, `/sec-review`, `/test-coverage` |
| **M2** | Agent-PythonScanner | Agent-TreeSitter | No | Python scanner (`cryptography`, `hashlib`, `ssl`), Pass 1 constant propagation, quantum tagging via `//go:embed` | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **M2** | Agent-CycloneDXOutput | Agent-PythonScanner | No | Wire CycloneDX 1.7 JSON output end-to-end: findings → structs → file | `/lint`, `/test-coverage` |
| **M2** | **Orchestrator gate** | All M2 agents | — | Validate end-to-end scan produces valid CBOM JSON | `/lint`, `/sec-review`, `/test-coverage`, `/build-cross` |
| **M3** | Agent-JSScanner | M2 complete | Yes | JS/TS scanner (Node.js `crypto`, `jsonwebtoken`, `forge`) | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **M3** | Agent-RegexLayer | M2 complete | Yes | Regex layer (PEM headers, key blobs, algorithm strings), `.env`/`.properties`/YAML config scanner | `/lint`, `/test-coverage` |
| **M3** | Agent-SARIF | M2 complete | Yes | SARIF 2.1 output writer (full implementation) | `/lint`, `/test-coverage` |
| **M3** | Agent-PDFReport | M2 complete | Yes | `maroto` PDF report — findings table, severity chart, quantum status summary | `/lint`, `/test-coverage` |
| **M3** | **Orchestrator gate** | All M3 agents | — | Merge scanner registry, validate 2 languages + SARIF + PDF output | `/lint`, `/sec-review`, `/test-coverage`, `/build-cross` |
| **M4** | Agent-JavaScanner | M3 complete | No | Java scanner (JCA/JCE, Bouncy Castle) | `/new-scanner`, `/lint`, `/sec-review`, `/test-coverage`, `/fuzz` |
| **M4** | Agent-OpenGrepIntegration | Agent-JavaScanner | No | OpenGrep subprocess integration, result merging with Pass 1 findings | `/lint`, `/sec-review`, `/test-coverage` |
| **M4** | Agent-OpenGrepRules-Java | Agent-OpenGrepIntegration | Yes | `scanner/rules/java.yml` — hardcoded key, static IV, weak PRNG taint rules | `/new-opengrep-rule`, `/lint` |
| **M4** | Agent-OpenGrepRules-PythonJS | Agent-OpenGrepIntegration | Yes | `scanner/rules/python.yml` + `javascript.yml` — taint rules | `/new-opengrep-rule`, `/lint` |
| **M4** | **Orchestrator gate** | All M4 agents | — | Validate 3 languages + Pass 2 taint results merged correctly | `/lint`, `/sec-review`, `/dep-audit`, `/test-coverage`, `/fuzz`, `/build-cross` |
| **M5** | Agent-PolicyEngine | M4 complete | Yes | YAML policy parser (Koanf), rule evaluator, PASS/FAIL/WARN exit codes, `--fail-on` flag | `/lint`, `/sec-review`, `/test-coverage` |
| **M5** | Agent-CBOMDiff | M4 complete | Yes | `cbom diff` engine — added/removed/changed findings, text + JSON diff output | `/lint`, `/test-coverage` |
| **M5** | **Orchestrator gate** | All M5 agents | — | Validate policy check + diff against fixture CBOMs | `/lint`, `/sec-review`, `/test-coverage`, `/build-cross` |
| **M6** | Agent-CICD | M5 complete | Yes | GitHub Actions `cbom-action`, GitLab CI template | `/lint`, `/build-cross` |
| **M6** | Agent-Performance | M5 complete | Yes | Goroutine-parallel file scanning, benchmark suite, validate 100k LOC Java < 5 min | `/benchmark`, `/profile` |
| **M6** | ~~Agent-PDFReport~~ | — | — | *(moved to M3)* | — |
| **M6** | Agent-SchemaValidation | M5 complete | Yes | Embed CycloneDX 1.7 JSON schema, `cbom scan --validate`, 100% schema pass rate | `/lint`, `/test-coverage` |
| **M6** | **Orchestrator gate** | All M6 agents | — | Full Phase 1 milestone close | `/lint`, `/sec-review`, `/dep-audit`, `/test-coverage`, `/fuzz`, `/benchmark`, `/build-cross` |

---

## Orchestrator Rules

1. **Never write implementation code.** Assign, coordinate, merge, validate only.
2. **Never hand off broken code.** Run `/lint` + `/sec-review` after every subagent before assigning the next.
3. **Parallel agents get the same base.** Ensure the shared codebase compiles cleanly before launching parallel agents.
4. **Merge integration points explicitly.** Scanner registry (`cli/internal/scanner/registry.go`) and output format registration are the orchestrator's responsibility to merge after parallel agents complete.
5. **Milestone-close gates are non-negotiable.** All skills in the orchestrator gate row must pass before the milestone is marked complete. No exceptions.
6. **Escalate blockers immediately.** If a gate fails and cannot be resolved within the current agent context, surface it to the user before proceeding.

---

## Phase 1 Success Criteria (from `docs/08-roadmap.md`)

| Criterion | Gate |
|---|---|
| Scans a 100k LOC Java project in < 5 minutes | `/benchmark` at M6 |
| False positive rate < 10% for High/Critical findings | Fixture corpus test at M6 orchestrator gate |
| CycloneDX 1.7 schema validation passes 100% | Agent-SchemaValidation + M6 orchestrator gate |
| No panics on malformed input | `/fuzz` at M2, M3, M4 orchestrator gates |
| All platforms build and run | `/build-cross` at every milestone gate |
| No HIGH/CRITICAL security findings in CLI code | `/sec-review` at every milestone gate |
