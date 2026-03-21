# CipherRadar — VS Code Extension

Cryptography Bill of Materials (CBOM) scanner for VS Code. Find, classify, and fix cryptographic vulnerabilities directly in your editor.

## Features

- **Inline diagnostics** — cryptographic findings appear as squiggly underlines with severity-mapped colors (error for deprecated algorithms, warning for quantum-vulnerable, info for quantum-safe)
- **Hover details** — hover over a finding to see algorithm name, quantum security status, PQC replacement recommendation, and compliance tags
- **Quick fixes** — "Fix with CipherRadar" triggers LLM-assisted remediation via the backend API; "Suppress" adds a `// cradar:ignore` comment
- **Sidebar panel** — dedicated activity bar panel showing all findings grouped by severity, with click-to-navigate
- **Status bar** — scan status indicator and finding count badge

## Requirements

- [cradar CLI](https://github.com/nk-sentinel/cipherradar) installed and on `$PATH` (or configure `cipherradar.cradarPath`)
- VS Code 1.90.0 or later

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `cipherradar.cradarPath` | `"cradar"` | Path to the cradar CLI binary |
| `cipherradar.autoScan` | `true` | Automatically scan files on save |
| `cipherradar.apiUrl` | `""` | Backend API URL for LLM remediation |
| `cipherradar.apiKey` | `""` | API key for backend authentication |
| `cipherradar.severityMinLevel` | `"information"` | Minimum severity to display |

## Commands

| Command | Description |
|---|---|
| `CipherRadar: Scan Current File` | Scan the active editor file |
| `CipherRadar: Scan Workspace` | Scan all files in the workspace |
| `CipherRadar: Clear Diagnostics` | Clear all CipherRadar diagnostics |

## How It Works

1. On file save (or manual trigger), the extension invokes `cradar scan --format sarif --file <path>`
2. SARIF 2.1 JSON output is parsed into VS Code diagnostics
3. Findings are displayed inline, in the sidebar, and in the status bar
4. Optional: LLM-assisted remediation via the CipherRadar backend API

## Development

```bash
cd extensions/vscode
npm install
npm run compile
# Press F5 in VS Code to launch the Extension Development Host
```
