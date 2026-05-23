# Licensing

CipherRadar is an **open-core** project. Different directories are licensed differently. The licensing of each top-level directory is summarised below; the authoritative source is the `LICENSE` (or equivalent) file inside each directory.

## Per-directory licensing

| Directory | License | Notes |
|---|---|---|
| `cli/` | **Apache License 2.0** — see `cli/LICENSE` | The cradar CLI binary, scanners, OpenGrep rule embedding, and CycloneDX 1.7 output. Free for any use, commercial or otherwise, subject to the Apache 2.0 terms. |
| `scanner/` | Apache License 2.0 (same terms as `cli/`) | Shared OpenGrep rule sources, library-to-asset-type mappings, and tree-sitter grammar configs. Embedded into `cli/` at build time via `go generate`. |
| `docs/` | Apache License 2.0 (same terms as `cli/`) | Design documentation, ADRs, and the CLI usage guide. |
| `logo/` | (Trademark — see below) | The CipherRadar name and logo are trademarks of the project owner and are not covered by the Apache 2.0 grant. Use of the binary is fine; redistribution of the name/logo in derivative branding requires written permission. |
| `backend/` | **Not yet licensed for public use.** | Python/FastAPI + Taskiq backend. Source is in the repository but no license has been granted at this time. Any use, copying, modification, or distribution requires explicit written permission from the project owner. A formal commercial / source-available license (BSL / Elastic / FSL style) will be added before any public deployment or external contribution. |
| `frontend/` | **Not yet licensed for public use.** | React 19 + TypeScript dashboard. Same status as `backend/`. |
| `deploy/` | **Not yet licensed for public use.** | Docker Compose / Helm manifests for the backend + frontend. Same status as `backend/`. |
| `extensions/`, `plugins/` | TBD | Likely Apache 2.0 once concrete content lands; ask. |

## What this means in practice

- **You can freely use the `cradar` CLI** — the binary, its OpenGrep rules, its CBOM output — under Apache 2.0. Include it in your CI, redistribute it, modify it, build commercial products on top of it. Standard Apache 2.0 obligations apply (preserve the LICENSE / NOTICE, mark modifications).
- **You cannot use the web portal source** (`backend/`, `frontend/`, `deploy/`) without permission. The source is published for transparency and for eventual paid customers, not as open source. This will be formalised in a future commercial license; for now, treat those directories as proprietary.

## Contact

Questions about licensing or commercial use of the backend / frontend: open a GitHub issue with the label `licensing` or email the project owner.
