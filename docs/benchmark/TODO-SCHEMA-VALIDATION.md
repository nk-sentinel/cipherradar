# RESOLVED: CycloneDX 1.7 Schema Validation Errors

**Status:** Resolved 2026-05-25
**Resolved by:** feature/cbom-export-quality, commit 1 (see `docs/superpowers/specs/2026-05-25-cbom-export-quality-design.md`)

## History

Originally filed 2026-03-23 with 37 enum-validation failures across `algorithmFamily`,
`cryptoFunctions`, `mode`, `padding`. All 37 were resolved by the normalization maps
in `cli/internal/output/converter.go` (algorithmFamilyMap, cryptoFunctionMap, etc.)
before this commit landed.

Two additional bugs were discovered during the 2026-05-25 audit:

- **AlgorithmPrimitive bypass** — `HARDCODED-SECRET` (from `config_scanner.go`) and
  `CRYPTO-LIBRARY-IMPORT` (from OpenGrep rules) were cast straight to
  `cyclonedx17.Primitive` without normalization. Fixed in `convertCryptoProperties`
  with a `rerouteMarker` switch + `canonicalTokenPrimitive` map. Source cleanup
  in `config_scanner.go` removes the offending `AlgorithmPrimitive` field.

- **library assetType** — emitted as-is from OpenGrep inventory rules; not in
  CycloneDX 1.7 enum. Fixed per ADR-040 (emit as `type: library` component).

The `rerouteMarker` was extended in the same audit to also catch protocol tokens
(SSH, TLS-*, IKE), material tokens (INITIALIZATION-VECTOR, SYMMETRIC-KEY), and
certificate tokens (X509, CERTIFICATE-X509) — same bug shape, found by reviewing
scanner rule emissions exhaustively.

## Preventing regressions

`--strict-validate` flag (added in this commit) fails the scan if the
`validationTally` registers any non-zero fall-through during CycloneDX conversion.
Default behavior warns to stderr; CI should run with `--strict-validate`.
