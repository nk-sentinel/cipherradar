# ADR-003: CodeQL Independence — CBOM Generation Must Work Without a Build

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-15 |
| **Deciders** | Architecture session |

---

## Context

CodeQL is the most powerful open-source static analysis engine for crypto detection. The `cryptobom-forge` tool (Santander) uses CodeQL SARIF output as its input. GitHub's PQC queries are CodeQL-based.

However, CodeQL has a critical constraint: **compiled languages (C/C++, C#, Go, Swift) require a successful build before CodeQL can extract a database.** Java has a buildless mode but with accuracy trade-offs.

The question was raised: should CipherRadar be built on top of CodeQL, or should it be independent?

## Decision

**CipherRadar must work without CodeQL and without requiring the target application to be built.**

CodeQL may be offered as an optional integration in a future phase, but it must never be a requirement.

## Rationale

The primary use case is CBOM generation — not full security vulnerability detection.

For CBOM, the dominant crypto pattern is:
```java
Cipher.getInstance("AES/CBC/PKCS5Padding");  // literal string — ~80–85% of real-world cases
```

This pattern is visible directly in source code and requires no build, no type resolution, and no compiler involvement to detect. Analysis of real-world codebases shows 80–85% of crypto API calls use direct literals or single-hop variable assignments — all resolvable by source-only analysis.

Additionally:
- Many organisations scan repositories that cannot be built in CI (legacy codebases, incomplete dependency resolution, complex build environments)
- Requiring a build adds significant CI/CD setup overhead, blocking adoption
- Build failures should not prevent crypto discovery
- Buildless scanning enables scanning of third-party/vendor code without a build environment
- Competing tools (sonar-cryptography, Semgrep) work without builds and cover the majority of CBOM use cases

## Consequences

- Positive: Zero-friction adoption — `cbom scan ./myproject` works on any codebase immediately
- Positive: Works on incomplete, legacy, or broken codebases
- Positive: Enables scanning of vendor/third-party source drops without build setup
- Negative: Some deep inter-procedural flows (5+ hops across files) will be `confidence: unresolved`
- Negative: Cannot resolve runtime-configured algorithm selection (acceptable — no tool can)
- Mitigation: Unresolved parameters are explicitly marked in CBOM output; crypto API call location is still recorded

## Build Requirement by Language (Reference)

| Language | Build Required for CodeQL | CipherRadar Approach |
|---|---|---|
| JavaScript / TypeScript | No | tree-sitter direct |
| Python | No | tree-sitter direct |
| Ruby | No | tree-sitter direct |
| Java | No (buildless mode) / Yes (full) | tree-sitter + Joern (no build) |
| Kotlin | No | tree-sitter direct |
| C# | Yes | tree-sitter + Semgrep (no build) |
| Go | Yes | tree-sitter direct |
| C / C++ | Yes | tree-sitter + Joern (no build) |
| Swift | Yes | tree-sitter direct |

## Future Consideration

A CodeQL integration may be added as an **optional deep-scan mode** in Phase 4, triggered only when:
- A working build environment is detected
- The user explicitly opts in with `--deep-scan`
- Results supplement (not replace) the source-only scan

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/03-detection-engine.md` | No-build-required constraint is a core design principle of all three passes |
| `docs/01-product-design.md` | Non-Goals section: "No build required" listed as a Phase 1 non-goal to abandon |
| `docs/08-roadmap.md` | OQ-004: CodeQL as optional Phase 4 deep-scan — evaluated at Phase 4 planning |
