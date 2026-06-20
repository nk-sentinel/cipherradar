# CipherRadar CLI

CipherRadar is a source-code-first Cryptography Bill of Materials (CBOM) scanner. It identifies every cryptographic asset in a codebase — algorithms, protocols, certificates, key material — and produces CycloneDX 1.7 output, post-quantum readiness reports, and policy verdicts.

## What's in this archive

| File | Purpose |
|---|---|
| `cradar` (or `cradar.exe`) | The CLI binary |
| `opengrep` (`opengrep.exe`) | OpenGrep — taint-analysis engine for Pass 2 (cradar-full only) |
| `yr` (`yr.exe`) | YARA-X — binary content-scanning engine for Pass 3 (cradar-full only; opt-in via `--deep` / `--passes 3`) |
| `LICENSE` | Project license |
| `CHANGELOG.md` | What changed in this release and prior releases |
| `docs/` | Full CLI usage guide — start at `docs/README.md` |

## Quick start

```bash
# Verify the binary
./cradar version

# Scan a project (terminal-friendly summary by default on TTY)
./cradar scan /path/to/project

# Produce a CycloneDX 1.7 CBOM
./cradar scan /path/to/project --format cyclonedx-json --output cbom.json --validate

# Add a baseline + diff for follow-up scans
./cradar init
./cradar scan . --output cbom.json
./cradar diff cbom.json cbom-after.json
```

## Where to look next

| Question | Where |
|---|---|
| What does each command do? | `docs/commands.md` |
| Which output format should I use? | `docs/output-formats.md` |
| How do I configure `.cradar.yml` or `policy.cradar.yml`? | `docs/configuration.md` |
| What do the exit codes mean (for CI)? | `docs/exit-codes.md` |
| How do I wire this into CI / pre-commit / a portal push? | `docs/workflows.md` |

## Online

- Source: https://github.com/nk-sentinel/cipherradar
- Issues: https://github.com/nk-sentinel/cipherradar/issues
- Latest release: https://github.com/nk-sentinel/cipherradar/releases/latest
