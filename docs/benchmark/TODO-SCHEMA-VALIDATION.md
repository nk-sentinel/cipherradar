# TODO: Fix CycloneDX 1.7 Schema Validation Errors

**Priority:** Medium
**Found:** 2026-03-23
**Context:** Post-benchmark scanner improvements introduced 37 schema validation failures

## Problem

`cradar scan --validate` reports 37 errors against the CycloneDX 1.7 JSON schema. Our new scanner findings use non-standard enum values for:

1. **`algorithmFamily`** — values like `concatkdf`, `concatkdf-hmac`, `x963kdf`, `fernet`, `poly1305`, `aes-cmac`, `3des-cmac` are not in the CycloneDX 1.7 `cryptoAlgorithmFamily` enum
2. **`cryptoFunctions`** — values like `cipher-suite`, `key-agreement`, `generate`, `mac` may not match the schema's allowed function list
3. **`mode`** — some mode strings may not match the CycloneDX enum
4. **`padding`** — some padding values may not match

## Root Cause

The FN fixes and CBOM inventory improvements added new algorithm families and crypto function types that were named for clarity but don't map to CycloneDX 1.7's restricted enum values.

## Fix Approach

1. Read the CycloneDX 1.7 schema at `cli/internal/validation/schema/` to get the exact allowed enum values
2. Create a mapping from our internal names to CycloneDX-standard names
3. Apply the mapping in `cli/internal/output/converter.go` before serialization
4. Re-run `--validate` to confirm 0 errors

## Affected Files

- `cli/internal/scanner/java/java_scanner.go` — algorithmFamily values
- `cli/internal/scanner/python/python_scanner.go` — algorithmFamily values
- `cli/internal/output/converter.go` — the mapping layer
