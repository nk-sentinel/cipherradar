# ADR-039: YARA-X Integration for Binary Crypto Detection

**Status:** Proposed
**Date:** 2026-05-24
**Supersedes:** —
**Related:** ADR-016 (container image scanning), ADR-038 (installer checksum), pending Phase 5 binary-deep-scan items

## Context

cradar ships `yr` (YARA-X v1.14.0) inside every `cradar-full` release archive (~28 MB per platform), and `cradar install-tools` downloads it for users of the lite archive. **The binary is never invoked at runtime.** The internal binary scanner at `cli/internal/scanner/binary/` does pure native pattern matching for crypto constants (S-boxes, round constants, OIDs) in `.so/.dll/.dylib/.exe/.class/.jar/.whl` files. It uses no YARA rules.

This creates three problems:

1. **Vestigial weight.** Every cradar-full download includes ~28 MB of inert binary.
2. **Capability gap.** Container scanning (ADR-016) extracts layer filesystems composed mostly of compiled binaries. The current pattern table catches a narrow set; YARA's signature language is far more expressive (regex-over-bytes, conditional logic, string sets, file metadata).
3. **Roadmap mismatch.** Phase 5's "binary deep scanning" and "WASM / edge function scanning" deliverables presume a real YARA-X integration that doesn't exist yet.

## Decision

Wire YARA-X into the scan pipeline as a real binary-content scanner. Specifically:

1. **New scanner package** `cli/internal/scanner/yarax/` that:
   - Discovers `yr` via the same lookup order as `opengrep` (next-to-cradar → `$CRADAR_TOOLS_DIR/yr` → `~/.cradar/tools/yr` → `$PATH`).
   - Soft-skips if `yr` is absent (matches OpenGrep's behavior on lite installs).
   - Invokes `yr scan --json --rules <rules-dir> <target>` per file, parses the JSON, maps each match to a `types.Finding`.
   - Implements the `scanner.Scanner` interface so it composes with the existing per-file dispatch in `walker.go`.

2. **Embedded YARA-X ruleset** at `scanner/yara-rules/*.yar`:
   - Synced into `cli/internal/yararules/data/` via `go generate` (same pattern as OpenGrep rules).
   - Initial ~15 rules covering: OpenSSL version strings, libsodium / BoringSSL / mbedTLS magic, embedded PEM blobs in binaries, common RSA-private-key markers, AES S-box / round-constant byte patterns (re-expressed from the native table for ruleset uniformity), JWT signing-key patterns.

3. **Extension registration.** YARA-X scanner registers for `.so .dll .dylib .exe .class .jar .whl .a .o .wasm`. The native binary scanner stays — they run in parallel; native finds what its pattern table covers, YARA-X catches the broader signature space. Future deprecation of the native scanner is possible once YARA-X rule coverage matches, but explicitly not required by this ADR.

4. **Container scan composition.** `cradar scan --container <image>` (ADR-016) already extracts the OCI layer filesystem and walks it through the standard scanner registry. With YARA-X registered, no additional plumbing is needed for it to fire on container layer binaries — the registration covers both flows.

5. **Output mapping.** YARA-X findings flow through the existing `types.Finding` → CycloneDX converter:
   - `cryptoProperties.assetType`: `algorithm` for crypto-constant matches; `related-crypto-material` for embedded key blobs; `certificate` for embedded PEM/DER cert detections.
   - `cryptoProperties.algorithmProperties.primitive`: populated from YARA-rule `meta` (each rule declares `cbom_primitive = "MD5"` etc., parallel to the OpenGrep `metadata.cbom-primitive` field from PR #4).
   - `cryptoProperties.algorithmProperties.algorithmFamily`, `mode`, `padding`: populated where the rule's match exposes them.

6. **Pass attribution.** YARA-X is **Pass 3** (binary). Pass 1 = native AST + regex. Pass 2 = OpenGrep taint. Pass 3 = YARA-X binary. The existing `--passes` flag gains `3` as a valid value. Default scan runs all three when their tools are available.

## Alternatives considered

1. **Remove YARA-X from the cradar-full archive and from install-tools.** Cheapest. Honest about today's capability. Lose ~28 MB per platform. **Rejected** because the user explicitly intends to keep building toward binary scanning ("Option B" from the rc4 / rc5 discussion).

2. **Replace YARA-X with `go-yara` (libyara CGo bindings).** Pure Go process, no subprocess. **Rejected** because libyara is YARA classic, not YARA-X — different rule dialect, no Go-native YARA-X binding exists yet. Subprocess to `yr` matches the OpenGrep precedent.

3. **Build a native rule engine on top of the existing `patterns.go` byte table.** Extend the table format with regex, conditional logic, file-metadata predicates. **Rejected** as reinventing YARA badly — same expressiveness goal, more code, less ecosystem (no rules from upstream YARA-X projects, no community rule sharing).

4. **Use OpenGrep's bytecode mode for binary scanning.** OpenGrep's Semgrep ancestry does support bytecode patterns. **Rejected** because (a) the bytecode mode is more limited than YARA's, and (b) we already invest in subprocess management for OpenGrep; YARA-X just slots in alongside.

5. **Defer until Phase 5 ships properly.** Keep shipping the inert `yr` for forward compatibility. **Rejected** — the inert binary is currently a quality smell visible to anyone inspecting `cradar-full`, and the integration cost is bounded (~1-2 weeks).

## Trust / supply chain

YARA-X binaries are downloaded via the same `cradar install-tools` path as OpenGrep, and as of ADR-038 the OpenGrep download is SHA-256-verified via the GitHub Releases API `digest` field. The YARA-X download path was not updated in ADR-038 because YARA-X wasn't being used; that becomes a gap to close as part of this work. **In-scope for this ADR's implementation: extend ADR-038's verification pattern to the YARA-X download.**

## Consequences

- `cradar scan <dir>` and `cradar scan --container <image>` both gain crypto-asset detection inside compiled binaries (with `yr` available).
- `cradar-full` archive contents stay the same (~60 MB) — `yr` is no longer vestigial.
- New embedded rule corpus to maintain in `scanner/yara-rules/` alongside `scanner/rules/`. Same lifecycle policy (per ADR-035) — rules carry `maturity`, `default_enabled`, `noise_risk`.
- `--passes 3` becomes a runnable mode. Default-pass set extends to `1,2,3` when all tools available.
- `cradar rules list --pass 3` discoverability for the new ruleset.
- Slight scan-time overhead for projects with many binaries; YARA-X is fast (Rust core) but per-file invocation adds subprocess startup time. Mitigation: batch multiple binaries per `yr` invocation where the rule corpus allows.
- Future ADR (Phase 5 binary deep scan) extends the rule corpus; this ADR only establishes the integration.

## Implementation scope

Tracked separately in `docs/superpowers/specs/2026-05-24-yarax-binary-scanning-design.md`. Sub-PR breakdown:

- **A** — Runner + scanner package skeleton + lookup + extension registration. Soft-skip when `yr` absent. No rules yet; `--debug` shows YARA-X being invoked. (~3-4 days)
- **B** — Embedded starter ruleset (~15 rules) + `go generate` sync + `cbom-primitive` metadata mapping. Produces first real Pass-3 findings. (~3-4 days)
- **C** — `--passes 3` flag handling + default-pass-set extension + YARA-X SHA-256 download verification (close the ADR-038 gap). (~2-3 days)
- **D** — Docs (CLI guide update, ADR final, CHANGELOG, version bump) + container-scan smoke test verifying YARA-X fires on `--container` flow. (~1-2 days)

Total: roughly two weeks of focused work, shippable as `0.3.0-rc.1` or `0.2.x` minor depending on cumulative scope at the time.
