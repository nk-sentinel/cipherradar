# ADR-002: Parsing Backbone — tree-sitter as the Multi-Language AST Foundation

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-15 |
| **Deciders** | Architecture session |

---

## Context

The scanner must support 12+ programming languages. Each language requires an AST parser to identify cryptographic API calls. Two broad approaches exist:

1. **Per-language native parsers** — one dedicated parser per language (JavaParser for Java, Roslyn for C#, go/ast for Go, etc.)
2. **Unified multi-language parser** — one parsing framework that handles all languages through a common API

The choice has significant implications for development velocity, maintenance burden, and long-term extensibility.

## Decision

**tree-sitter** as the primary parsing backbone for all languages, with language-native semantic analysis layered on top for Java, Kotlin, C#, and TypeScript where type resolution is required.

## Rationale

- tree-sitter provides 40+ battle-tested language grammars via a single C library with bindings in Go, Python, Rust, Node.js, and others
- Error-tolerant parsing — handles incomplete or syntactically broken code without failing (critical for real-world codebases)
- Incremental re-parsing — re-parses only changed sections of a file; critical for fast differential scanning
- Unified CST query language — the same `(call_expression function: (identifier) @name)` pattern syntax works across all languages
- Used in production by: GitHub Copilot, Neovim, Zed editor, GitHub's semantic analysis — proven at scale
- Adding a new language = adding one grammar file; no new parser implementation required
- Actively maintained by GitHub; long-term support assured

## Consequences

- Positive: Adding language #13 or #14 requires minimal effort — just a new grammar + library API model
- Positive: Single codebase for all language parsing logic
- Positive: Handles malformed/partial code gracefully — important for scanning work-in-progress branches
- Negative: tree-sitter produces a Concrete Syntax Tree (CST), not a semantically enriched AST — no type information
- Negative: Cannot resolve `crypto` in `Constants.CIPHER` to its declared type without a semantic layer
- Mitigation: Language-native semantic analysis (JavaParser, Roslyn, TypeScript Compiler API) is layered on top only for the languages where type resolution meaningfully improves accuracy

## Alternatives Considered and Rejected

| Option | Reason Rejected |
|---|---|
| Per-language native parsers only | One parser per language = 12+ separate implementations; high maintenance burden; language #13 is a large effort each time |
| ANTLR grammars | Requires writing/maintaining grammar files per language; tree-sitter grammars already exist and are maintained upstream |
| Language Server Protocol (LSP) | LSPs require a running language server per file; high overhead; complex lifecycle management; overkill for batch scanning |
| Regex only | Fast but misses structural context; high false positive rate; cannot handle nested expressions |

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/03-detection-engine.md` | tree-sitter is the foundation of Pass 1; language coverage matrix lists tree-sitter grammar per language |
| `docs/07-tech-stack.md` | go-tree-sitter listed as a CLI dependency |
| `docs/08-roadmap.md` | Phase 1 deliverable: tree-sitter integration with language detection and dispatch |
