# YARA-X starter ruleset

The `.yar` files in this directory are the source-of-truth ruleset for cradar's Pass 3 (YARA-X) binary scanner. They detect cryptographic libraries, embedded key material, and algorithm-specific byte constants in compiled artifacts (ELF, PE, Mach-O, WASM).

## Layout

```
scanner/yara-rules/
├── openssl-versions.yar              # OpenSSL 1.0 / 1.1 / 3.0 / 3.1 banners
├── crypto-library-signatures.yar     # libsodium, BoringSSL, mbedTLS markers
├── embedded-pem-blobs.yar            # PEM cert + private-key markers
├── symmetric-cipher-constants.yar    # AES S-boxes, Rcon, DES S-box
├── hash-algorithm-constants.yar      # MD5/SHA-1/SHA-256 initial state
└── README.md                         # (this file)
```

Files in `cli/internal/yararules/data/` are an embedded copy synced via `go generate ./internal/yararules` and shipped inside the cradar binary via `//go:embed`. **The source-of-truth lives here**; never edit the embedded copies directly.

## Meta-block vocabulary

Every rule MUST set `meta.cbom_primitive`. The parser in `cli/internal/scanner/yarax/canonicalize.go` reads this field and uses it to populate `CryptoProperties.AlgorithmPrimitive` on every finding the rule produces — without it, the finding has no asset identity in the CBOM.

The vocabulary mirrors `cbom-primitive` / `cbom-asset-type` / `cbom-library` / `category` / `maturity` / `default_enabled` / `noise_risk` already used by the OpenGrep rules in `scanner/rules/`. Use the same canonical tokens across both engines (see `cli/internal/opengrep/parser.go:canonicalizePrimitive` for the full token list).

| Meta key | Required | Typical values |
|---|---|---|
| `cbom_primitive` | yes | `AES`, `OPENSSL-3.0`, `RSA`, `X.509`, `LIBSODIUM` |
| `cbom_asset_type` | yes | `algorithm`, `library`, `protocol`, `certificate`, `related-crypto-material` |
| `cbom_library` | when asset is a library | `openssl`, `libsodium`, `boringssl`, `mbedtls` |
| `category` | yes | `inventory` or `security` |
| `maturity` | yes | `experimental`, `stable`, `deprecated` |
| `default_enabled` | yes | `"true"` or `"false"` (string — YARA-X meta values are not booleans) |
| `noise_risk` | yes | `low`, `medium`, `high` |
| `author` | recommended | `"cradar"` for in-tree rules |
| `description` | recommended | One-line human description; ends up in CBOM `Description` |

Note: YARA-X `meta` values are typed (string / int / bool) but cradar's YAML-style vocabulary uses string-encoded booleans (`"true"` / `"false"`) for consistency with the OpenGrep ruleset.

## Adding a rule

1. Pick the right file by topic (or add a new one; one logical area per file keeps reviews tractable).
2. Set every required meta key. Use canonical tokens — if your rule detects AES-GCM specifically, write `cbom_primitive = "AES-GCM"`, not `"AES_GCM"` or `"aes-gcm"`.
3. Anchor patterns to reduce false positives. Hex-byte tables and `\x00`-terminated strings are good anchors; bare substrings are not.
4. Run `go generate ./internal/yararules` from `cli/` to sync the embedded copy.
5. Run `go test ./internal/scanner/yarax/...` — `TestRuleset_AllRulesHaveCbomPrimitive` will fail if you forgot `cbom_primitive` on any rule.
6. Test against a real binary fixture in `CipherRadarTestProj/binaries/` (or add a new fixture if your rule covers a new pattern).

## What this ruleset does NOT cover

These are deferred or out of scope:

- **Post-quantum algorithms** — no Kyber/Dilithium/Falcon byte signatures yet. Add when fixtures exist.
- **Asymmetric algorithm constants** — RSA / ECDSA don't have universal byte signatures (parameters vary by curve), so detection here relies on PEM blobs and OpenSSL banners rather than constants.
- **Compressed binaries** — UPX-packed or otherwise compressed binaries hide all of these patterns. No defeating the packer at the YARA layer.
- **Architecture-specific intrinsics** — AES-NI instructions have a different byte signature than table-based AES; not yet covered.
- **Hardware crypto module markers** — no Intel SGX / ARM TrustZone / Apple Secure Enclave signatures yet.

## Performance budget

YARA-X compiles the entire ruleset once per scanner invocation and reuses the compiled form across files. Per ADR-039, the 50-rule budget keeps compile + scan under 100ms per 10MB binary on a modern x86_64 box. Current count: 15 rules. Stay under 50 unless a benchmark says otherwise.
