# ADR-029: VS Code Extension Architecture — Direct Diagnostic Provider

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-22 |
| **Deciders** | Architecture session |

---

## Context

Developers spend the majority of their time in an IDE. Surfacing cryptographic findings directly in the editor — at the moment of writing code — provides faster feedback than CI/CD pipeline results or dashboard reports. VS Code is the most widely used editor, with ~73% market share among developers (Stack Overflow 2025 survey).

The extension must invoke the `cradar` CLI (already installed on the developer's machine) and present findings using native VS Code UI patterns: diagnostics (squiggly underlines), hover tooltips, code actions, and a sidebar panel.

---

## Decision

### Direct Diagnostic Provider (not LSP)

The extension uses the VS Code Diagnostic API directly rather than implementing a Language Server Protocol (LSP) server. Rationale: CipherRadar is not a language server — it does not provide completions, definitions, or references. It produces a fixed set of diagnostics per file. The LSP abstraction adds complexity (client-server protocol, JSON-RPC, lifecycle management) without corresponding benefit.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  VS Code Extension (TypeScript)                     │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │ DiagProvider  │  │ HoverProvider│  │ CodeAction │ │
│  │              │  │              │  │ Provider   │ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘ │
│         │                 │                │        │
│  ┌──────▼─────────────────▼────────────────▼─────┐  │
│  │           SARIF Parser / Cache                │  │
│  └──────────────────┬────────────────────────────┘  │
│                     │                               │
│  ┌──────────────────▼────────────────────────────┐  │
│  │    cradar scan --format sarif --file <path>   │  │
│  │              (subprocess)                     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Components

**1. DiagnosticProvider** — Triggered on file save (`onDidSaveTextDocument`). Runs `cradar scan --format sarif --file <path>` as a subprocess. Parses SARIF 2.1 output into a `DiagnosticCollection`. Diagnostics are severity-mapped:
- Quantum-vulnerable algorithm → `DiagnosticSeverity.Warning`
- Deprecated algorithm (e.g. MD5, DES) → `DiagnosticSeverity.Error`
- Quantum-safe algorithm → `DiagnosticSeverity.Information`

**2. HoverProvider** — When the user hovers over a diagnostic range, displays:
- Algorithm name and type (symmetric, asymmetric, hash, etc.)
- Quantum security status (safe / vulnerable / unknown)
- Recommended PQC replacement (if applicable)
- NIST compliance status

**3. CodeActionProvider** — Offers quick-fix code actions on diagnostic ranges:
- "Fix with CipherRadar" — triggers LLM-assisted remediation via the backend API (ADR-027). Requires backend connection and API key configured in extension settings.
- "Suppress this finding" — adds a `// cradar:ignore <rule-id>` inline comment

**4. TreeView sidebar panel** — A dedicated sidebar panel (`activityBar` contribution) showing all findings in the current workspace, grouped by severity. Click-to-navigate to finding location. Refresh button re-scans the workspace.

**5. StatusBar item** — Bottom status bar showing:
- Scan status indicator (idle / scanning / error)
- Finding count badge (e.g. "CipherRadar: 3 findings")

### Configuration

Extension settings in `settings.json`:

```json
{
  "cradar.binaryPath": "/usr/local/bin/cradar",
  "cradar.scanOnSave": true,
  "cradar.apiEndpoint": "https://cradar.internal/api/v1",
  "cradar.apiKey": "",
  "cradar.severity.minLevel": "information"
}
```

---

## Options Considered

### Option A: LSP-based architecture (rejected)
A full Language Server Protocol implementation with a cradar language server process. Rejected because CipherRadar does not provide language intelligence features (completions, go-to-definition, rename). LSP adds a persistent server process, JSON-RPC protocol overhead, and client-server lifecycle management for a tool that produces batch diagnostics per file. The Diagnostic API is simpler and achieves the same user experience.

### Option B: Webview-based UI (rejected)
Custom HTML/CSS panels rendered in VS Code webviews for rich finding display. Rejected because native VS Code APIs (Diagnostics, Hover, TreeView) provide a more consistent and accessible user experience that follows VS Code UX conventions. Webviews are appropriate for dashboards but not for inline code feedback.

### Option C: SARIF Viewer extension integration (rejected)
Rely on the existing SARIF Viewer extension to display `cradar` SARIF output. Rejected because it provides no CipherRadar-specific UX (quantum status, remediation actions, agility score). The generic SARIF viewer cannot offer "Fix with CipherRadar" code actions or display quantum-specific hover information.

---

## Consequences

- **Positive:** Developers see cryptographic findings at write-time, not after CI/CD completes
- **Positive:** Native VS Code UX — diagnostics, hovers, code actions follow familiar patterns
- **Positive:** No persistent server process — `cradar` CLI invoked on demand
- **Positive:** Works offline (diagnostics from CLI); LLM remediation optional (requires backend)
- **Negative:** File-level scanning on save may feel slow for large files (mitigated by async subprocess)
- **Negative:** Extension depends on `cradar` CLI being installed and on `$PATH` or configured path
- **Negative:** LLM remediation requires separate backend connection — not available in offline mode

---

## Impact on Other Documents

| Document | What Changes |
|---|---|
| `docs/08-roadmap.md` | Phase 4: VS Code extension listed as deliverable |
| `docs/07-tech-stack.md` | VS Code Extension API, TypeScript added for IDE tooling |
| `cli/internal/cmd/scan.go` | `--file` flag for single-file scanning (may already exist) |
