# ADR-040: Library detections emit as CycloneDX type=library components

**Status:** Accepted
**Date:** 2026-05-25
**Context:** feature/cbom-export-quality, commit 1

## Context

OpenGrep inventory rules (`cli/internal/rules/data/*.yml` — `cbom-<lang>-crypto-library-import`)
and YARA-X starter rules (`cli/internal/yararules/data/openssl-versions.yar`,
`crypto-library-signatures.yar`) emit findings with `cbom-asset-type: library` /
`cbom_asset_type = "library"`. Library presence detection is valuable inventory data, but
"library" is not a valid value for CycloneDX 1.7's `cryptoProperties.assetType` enum
(`algorithm | certificate | protocol | related-crypto-material`).

## Decision

Library findings are emitted as regular CycloneDX components with `type: "library"` and
**no** `cryptoProperties` block. This matches CycloneDX's intended use of the
`type: library` component for SBOM library entries.

`convertFindingTally` in `cli/internal/output/converter.go` short-circuits on
`f.AssetType == "library"` and returns a `Component{Type: "library", ...}` without
populating `CryptoProperties`. Library detections still appear in text and PDF
outputs (which read from the same `types.Finding` source) — only the CycloneDX
JSON shape changes.

## Alternatives considered

- **Reroute to `assetType: algorithm` with algorithmFamily set.** Rejected: loses
  the "this is a library, not an algorithm" semantic and pollutes algorithm counts
  in PDF aggregators.
- **Drop library findings from CycloneDX JSON entirely.** Rejected: loses inventory
  data that downstream consumers (Dep-Track, portal) expect.

## Consequences

- CBOM JSON consumers that filtered by `assetType == "library"` will need to switch
  to `component.type == "library"`. Documented as a breaking change in CHANGELOG.
- The reverse direction (component.type == "library" → cryptoProperties.assetType)
  is no longer a round-trip; this is correct per CycloneDX 1.7 schema.
