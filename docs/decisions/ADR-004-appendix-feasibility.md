# ADR-004 Appendix: Taint Engine Feasibility Analysis

> This appendix supports [ADR-004](ADR-004-taint-engine-revision.md). It contains the detailed feasibility analysis that justified replacing the custom taint engine with Joern + Semgrep.

---

## Taint Analysis Complexity Spectrum

Taint analysis exists on a spectrum. The original design did not specify which level was intended:

| Level | Scope | Build Effort | Accuracy |
|---|---|---|---|
| Constant propagation | Single function, literal tracking | Weeks | ~90–95% |
| Intra-procedural dataflow | Single function, all variable types | 1–2 months | ~85–90% |
| Inter-procedural (same file) | Call graph within one file | 2–4 months | ~75–85% |
| Inter-procedural (cross-file) | Full project call graph | 6–12 months | ~65–75% |
| Full taint analysis | Program-wide, including libraries | Years | ~85–95% |

A production-grade full taint engine (the level implied by the original design) represents **years of engineering effort**. SonarQube's taint engine was built over 10+ years. CodeQL's dataflow engine is the result of academic research spanning a decade.

---

## CBOM vs Security Taint Requirements

Critically, CBOM taint requirements are fundamentally simpler than security vulnerability taint:

| Security Taint (SQLi/XSS) | CBOM Constant Propagation |
|---|---|
| Source: user-controlled input (HTTP, DB, file) | Source: **string/integer literals in code** |
| Sink: SQL query, HTML output, shell command | Sink: **crypto API function parameters** |
| Sanitisers change taint status | No sanitisers — track all crypto usage |
| Must model untrusted→trusted boundaries | Must resolve: **what value reaches this parameter?** |
| Needs path conditions and branch analysis | Mostly needs assignment chain resolution |

This is not taint analysis in the security sense — it is **constant propagation**, a standard compiler technique that is well-understood and significantly simpler to implement.

---

## Real-World Distribution of Crypto Patterns

Analysis of open-source codebases shows:

| Pattern | Prevalence | Resolvable Without Full Taint? |
|---|---|---|
| Direct literal: `Cipher.getInstance("AES/CBC")` | ~55% | Yes — trivially |
| Single-hop variable: `String s = "AES"; Cipher.getInstance(s)` | ~25% | Yes — constant propagation |
| Cross-function same file: `getAlgo()` returns literal | ~8% | Yes — simple call graph |
| Cross-file constants class | ~5% | Yes — symbol table pass |
| Deep multi-hop / config-driven | ~7% | Partial — Joern handles most |
| Runtime only (env var, DB) | ~5% | No tool can resolve this |

**~88% of crypto calls are resolvable without a full custom taint engine.**

---

## Risk Assessment: Building Custom vs Using Existing Tools

| Factor | Custom Taint Engine | Joern + Semgrep |
|---|---|---|
| Initial build time (3–4 languages) | 6–12 months | Weeks (integration only) |
| Languages covered at 12 months | 3–4 | 10+ (both tools already support them) |
| Ongoing maintenance | High — grows with every language | Low — upstream maintained |
| Expected accuracy | Lower than proven tools | Higher — years of production hardening |
| Audit / review | Custom internal code | Open-source, Apache 2.0 / LGPL |

Three mature open-source frameworks already solve this exact problem space.

---

## Why Joern

| Property | Detail |
|---|---|
| Maturity | Production-grade; used in academic research and industry security teams |
| Language support | Java, Kotlin, Python, JavaScript, C/C++, PHP, Go, Ruby |
| Approach | Code Property Graph (CPG) — unifies AST, CFG, PDG into one queryable graph |
| Taint tracking | Built-in taint tracking via Scala query API (Joern queries) |
| Build requirement | **No build required** — analyses source code directly |
| Integration | Headless mode via CLI and HTTP API; embeddable as a library |
| License | Apache 2.0 |
| Maintained by | ShiftLeft / Qwiet AI, with active open-source community |

---

## Why Semgrep

| Property | Detail |
|---|---|
| Taint mode | Declarative source→sink→sanitiser rules in YAML |
| Language support | 30+ languages including all CipherRadar targets |
| Rule maintenance | Rules are YAML — maintainable by engineers without compiler expertise |
| Speed | Fast (seconds to low minutes) |
| Ecosystem | 5,000+ community rules; OWASP, r2c, and community maintain crypto rules |
| Integration | CLI, GitHub Actions, API |
| License | LGPL (OSS engine); commercial rules tier available |

---

## Revised Accuracy Expectations by Pattern

| Scenario | Expected Accuracy | Primary Method |
|---|---|---|
| Direct literal | ~98% | tree-sitter AST |
| Single-hop variable | ~92% | Constant propagation |
| Multi-hop same function | ~82% | Constant propagation + Semgrep |
| Cross-function same file | ~76% | Semgrep taint / Joern |
| Cross-file constants class | ~70% | Symbol table pass + Joern |
| Deep multi-hop cross-file | ~55–65% | Joern |
| Runtime / config-driven | ~0% (unresolvable) | Marked `unresolved` |
| **Overall real-world** | **~85–90%** | Weighted by pattern prevalence |
