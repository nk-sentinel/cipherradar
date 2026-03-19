# ADR-011: Joern Integration Model — Subprocess Execution

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-19 |
| **Deciders** | Architecture session |

---

## Context

Joern (Apache 2.0, JVM/Scala) provides Code Property Graph (CPG) analysis for Pass 3 inter-procedural taint detection. Three deployment models were evaluated for integrating Joern with the CLI. This also resolves OQ-002 which deferred the Joern deployment model decision to Phase 2.

---

## Decision

**Subprocess execution** — the `cbom` CLI invokes Joern as a subprocess, the same pattern used for OpenGrep in Pass 2.

### Options Evaluated

| Option | Pros | Cons |
|---|---|---|
| **Subprocess** (chosen) | Simple, same pattern as OpenGrep, no JVM in Go process, Joern upgrades independent | JVM cold start (~5-10s), process overhead per scan |
| Persistent server (Joern server mode) | No cold start after first invocation, lower latency | Requires running daemon, complex lifecycle management, port management |
| Container (Joern in Docker) | Fully isolated, reproducible | Requires Docker, heavy (~1GB image), not suitable for CI/CD without Docker-in-Docker |

---

## Rationale

Subprocess execution matches the established OpenGrep integration pattern (ADR-009). Binary discovery follows the same resolution order: same directory as `cbom` binary → `$CBOM_TOOLS_DIR` → `~/.cbom/tools/` → `$PATH`. JVM cold start of 5-10s is acceptable because Pass 3 runs nightly, not on every PR — latency sensitivity is low. The `cbom-full` binary bundles Joern alongside OpenGrep (ADR-010), and `cbom install-tools` downloads Joern for lightweight binary users.

Phase 3 may revisit persistent server mode if scan frequency increases to the point where JVM cold start becomes a bottleneck (e.g., on-demand Pass 3 scans or sub-minute scan SLAs).

---

## Consequences

- **Positive:** Consistent with OpenGrep integration pattern — single tool discovery and invocation model across Pass 2 and Pass 3
- **Positive:** No JVM dependency in the Go binary itself — keeps `cbom` as a pure Go static binary
- **Positive:** Joern version upgradeable independently of the CLI release cycle
- **Negative:** 5-10s JVM cold start per Pass 3 invocation — acceptable for nightly cadence
- **Negative:** Joern binary is large (~50MB), increases `cbom-full` size

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/07-tech-stack.md` | Joern subprocess model confirmed; binary discovery follows same pattern as OpenGrep |
| `docs/12-phase2-implementation-plan.md` | A-M3 Agent-JoernIntegration uses subprocess execution model |
