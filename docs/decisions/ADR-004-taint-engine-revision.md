# ADR-004: Taint Engine Approach — Revised from Custom Build to Joern + Semgrep

| Field | Value |
|---|---|
| **Status** | Accepted (Supersedes original detection engine design) |
| **Date** | 2026-03-16 |
| **Deciders** | Architecture session |
| **Triggered by** | Feasibility challenge raised during architecture review |

---

## Context

The original detection engine design (documented in `docs/03-detection-engine.md` v1) included a **"custom taint engine"** as a core component, listed without a formal feasibility assessment.

During architecture review, the following challenge was raised:

> *"A feasibility analysis was not done on the custom taint engine. How confident are you to create this and how accurate do you expect it to be?"*

---

## Original Design (v1)

```
Detection Engine
├── tree-sitter (AST parsing)
├── Custom taint engine (inter-procedural dataflow)
└── Regex layer
```

The term "taint engine" was used without qualification, implying a full inter-procedural dataflow analysis system comparable to what SonarQube and CodeQL implement.

---

## Feasibility Summary

See [appendix](ADR-004-appendix-feasibility.md) for the full analysis. Key findings:

1. A full inter-procedural taint engine takes **6–12 months** to build for 3–4 languages; a program-wide engine takes years.
2. CBOM generation does not need full taint analysis — it needs **constant propagation** (a known, simpler problem).
3. ~88% of real-world crypto API calls are resolvable by constant propagation alone.
4. Two production-grade open-source tools (Joern, Semgrep) already cover the remaining cases.
5. Building custom would take longer and produce lower accuracy than using existing tools.

---

## Decision

**Replace the "custom taint engine" with a three-layer approach using existing proven frameworks:**

```
Detection Engine (Revised — v2)

Pass 1: tree-sitter + constant propagation  [fast, always runs]
  └── Detects ~80% of findings
  └── Direct literals, single-hop variables, simple concatenation
  └── Runs in seconds

Pass 2: Semgrep taint rules  [moderate, runs on PR/push]
  └── Detects ~8–10% additional findings
  └── Pre-written YAML rules per language for common crypto patterns
  └── Runs in minutes

Pass 3: Joern  [deep, runs scheduled/nightly]
  └── Detects ~3–5% additional findings (hard inter-procedural cases)
  └── Full CPG (Code Property Graph) with built-in taint tracking
  └── Supports: Java, Kotlin, Python, JS/TS, C/C++, PHP, Go
  └── Run as nightly job, not on every commit

Unresolved: confidence: unresolved
  └── Crypto API call IS recorded with location
  └── Algorithm parameter marked unknown
  └── Valid CBOM entry — analyst can investigate
```

Overall real-world accuracy: **~85–90%** (weighted by pattern prevalence). See [accuracy table](ADR-004-appendix-feasibility.md#revised-accuracy-expectations-by-pattern).

---

## Consequences

- Positive: Eliminates 6–12 months of custom taint engine development risk
- Positive: Higher accuracy than a custom-built engine due to using proven tools
- Positive: Joern and Semgrep are actively maintained — bugs fixed upstream
- Positive: Semgrep rules are auditable YAML — security team can review and contribute
- Negative: Dependency on two external frameworks (Joern, Semgrep) — version pinning required
- Negative: Joern is a JVM tool — adds Java runtime as a dependency for the deep scan pass
- Negative: Semgrep's OSS tier has some limitations; commercial tier may be needed for advanced rules
- Mitigation: Joern is isolated to Pass 3 (optional, nightly) — does not affect CLI startup time or basic usage

---

## Impact on Other Documents

| Document | Change Required |
|---|---|
| `docs/03-detection-engine.md` | Full revision — replace custom taint engine section with three-layer approach |
| `docs/07-tech-stack.md` | Add Joern and Semgrep; revise taint engine entry |
| `docs/08-roadmap.md` | Revise Phase 1 — constant propagation instead of taint engine; add Joern in Phase 2 |

---

## What Was Learned

When a design document says "build a custom X", always ask:

1. Has X been formally scoped? (What level of X?)
2. Does X already exist as an open-source tool?
3. What is the realistic build effort for X?
4. What is the accuracy expectation vs existing tools?

In this case, "custom taint engine" was an overstatement of what was actually needed (constant propagation) and an underestimation of what existed (Joern, Semgrep).
