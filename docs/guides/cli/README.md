# CipherRadar CLI Usage Guide

`cradar` is a source-code-first scanner that discovers every cryptographic asset in a project —
algorithms, protocols, certificates, key material — and emits a CycloneDX 1.7 Cryptography Bill
of Materials (CBOM). It runs offline against source trees and container images, gates pull
requests via policy rules, and integrates with SARIF code-scanning, SonarQube, and the
CipherRadar portal.

This guide covers everyday CLI use. It is also bundled as the `docs/README.md` inside every
release archive — keep it self-contained.

## Install

Two release artifacts ship per version on the [GitHub releases page](https://github.com/nk-sentinel/cipherradar/releases):

| Artifact      | Contents                                         | Use when                       |
|---------------|--------------------------------------------------|--------------------------------|
| `cradar`      | CLI only (~15 MB)                                | Internet access available      |
| `cradar-full` | CLI bundled with OpenGrep + YARA-X (~50 MB)      | Air-gapped or offline runners  |

Extract the archive, drop the binary on `$PATH`, and verify:

```bash
cradar version
```

Lightweight `cradar` users fetch the Pass-2 tools on first run:

```bash
cradar install-tools
```

This downloads OpenGrep and YARA-X to `~/.cradar/tools/`, verifies the SHA-256 of each binary
against the publisher's release digest, and makes both available to subsequent scans. The
`cradar-full` archive includes both tools already; `install-tools` is a no-op there.

## Quick start

```bash
# 1. Scan a project, terminal-friendly summary
cradar scan ./my-app

# 2. Scan and persist a CBOM (CycloneDX 1.7 JSON)
cradar scan ./my-app -o cbom.json --validate

# 3. Scaffold .cradar.yml + policy.cradar.yml
cradar init

# 4. Check the CBOM against a policy file
cradar policy check cbom.json --policy policy.cradar.yml --fail-on high

# 5. Compare two CBOMs to see what changed between releases
cradar diff cbom-before.json cbom-after.json

# 6. One-shot multi-format export (extension dispatch picks each writer)
cradar scan ./my-app -o cbom.json -o report.pdf -o issues.sarif
```

Inventory recall on the canonical test corpus is currently 100% (precision 100%) — see the
release benchmark report. Pass 2 (OpenGrep taint) is required for security findings; Pass 1
alone gives you the inventory.

## What's in this folder

| File                                         | Covers                                                                |
|----------------------------------------------|-----------------------------------------------------------------------|
| [`commands.md`](commands.md)                 | Every subcommand, every flag, with examples                            |
| [`output-formats.md`](output-formats.md)     | The five output formats, extension dispatch, TTY-aware stdout defaults |
| [`cbom-schema-reference.md`](cbom-schema-reference.md) | `component.type` / `assetType` values, per-field enums, which fields need action |
| [`configuration.md`](configuration.md)       | `.cradar.yml` and `policy.cradar.yml` schemas with annotated examples  |
| [`exit-codes.md`](exit-codes.md)             | Exit-code contract for CI pipelines                                    |
| [`workflows.md`](workflows.md)               | Common recipes — CI gate, baseline, container scan, push, hooks, etc.  |

## Help inside the binary

Every subcommand has built-in help:

```bash
cradar help
cradar scan --help
cradar policy check --help
```

Shell completion is available for bash, zsh, fish, and PowerShell — see `cradar completion --help`
or the [completion](commands.md#cradar-completion) section of the command reference.
