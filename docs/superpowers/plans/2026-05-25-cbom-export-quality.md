# CBOM Export Quality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve CBOM export correctness, completeness, and reporting quality across four sequential commits on `feature/cbom-export-quality` — schema-conformance, quantum readiness expansion, PDF report depth, and scan-time visibility.

**Architecture:** All work is in the Go CLI (`cli/`). Commit 1 fixes converter bugs at the boundary where scanner output meets CycloneDX 1.7. Commit 2 replaces the inline quantum table with a YAML data file. Commit 3 splits the 732-line PDF monolith into a focused package with new aggregators and an Option-D report layout. Commit 4 wires scanner progress events to stderr and adds an always-on final summary.

**Tech Stack:** Go 1.26.1, Cobra (CLI), maroto v2 (PDF), gopkg.in/yaml.v3 (config), santhosh-tekuri/jsonschema/v6 (schema validation), tree-sitter bindings (CGO_ENABLED=1), go-echarts/v2 (new — SVG charts).

**Source spec:** `docs/superpowers/specs/2026-05-25-cbom-export-quality-design.md`

**Conventions (per `CLAUDE.md`):**
- Imperative-mood lowercase commit messages, no co-author trailer.
- Stage specific files (`git add path1 path2`), never `git add .`.
- `gopkg.in/yaml.v3` for YAML.
- Run `go vet ./...` and `golangci-lint run` clean before each commit.
- `cd cli &&` prefix every Go command (module path is `cli/`).

---

## Pre-flight (run once before starting)

- [ ] **Confirm branch + clean tree**

```bash
cd /home/nk-sentinel/projects/cradar-cbom-export-quality
git status                         # expect clean
git rev-parse --abbrev-ref HEAD    # expect feature/cbom-export-quality
git log --oneline -5               # last commit should be a4f688f (spec correction)
```

- [ ] **Confirm tooling**

```bash
cd cli
go version                         # expect go1.26.1 or later
which golangci-lint                # expect /usr/local/bin/golangci-lint or similar
go build -o /tmp/cradar-baseline ./cmd/cradar  # baseline binary for regression diff
```

- [ ] **Capture baseline scan output for regression diff**

```bash
cd /home/nk-sentinel/projects/cradar-cbom-export-quality
mkdir -p /tmp/cbom-baseline
/tmp/cradar-baseline scan ./scanner/rules/python/ \
    --format cyclonedx-json --output /tmp/cbom-baseline/python.json \
    2>/tmp/cbom-baseline/python.stderr || true
```

This captures pre-change behavior so each commit can be diffed against it to confirm intended-only changes.

---

# Phase 1 — Validation Fix (Commit 1)

**Goal:** Two-bug fix + closed-set tally + `--strict-validate` flag. In-place edits to `cli/internal/output/converter.go`; no new package. Source-side cleanup in `config_scanner.go`.

**End-state commit message:**
```
feat(converter): close cyclonedx 1.7 enum gaps + add strict validation

Fix two bleed-through bugs introduced by scanner metadata:
- AlgorithmPrimitive bypass passed HARDCODED-SECRET, CRYPTO-LIBRARY-IMPORT
  straight to cyclonedx primitive enum; now normalized + rerouted.
- library asset_type from opengrep inventory rules (and yarax starter
  rules) had no cyclonedx 1.7 home; now emitted as type:library component
  without cryptoProperties per ADR-040.

Adds validationTally + --strict-validate flag so future bleed-through
is visible (default warn, opt-in fail).
```

---

### Task 1.1: Define closed-set enum literals + validationTally type

**Files:**
- Create: `cli/internal/output/validation.go`
- Test: `cli/internal/output/validation_test.go`

- [ ] **Step 1: Write the failing test**

`cli/internal/output/validation_test.go`:
```go
package output

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
)

func TestPrimitiveClosedSet(t *testing.T) {
	want := []cyclonedx17.Primitive{
		cyclonedx17.PrimitiveDRBG, cyclonedx17.PrimitiveMAC, cyclonedx17.PrimitiveBlockCipher,
		cyclonedx17.PrimitiveStreamCipher, cyclonedx17.PrimitiveSignature, cyclonedx17.PrimitiveHash,
		cyclonedx17.PrimitivePKE, cyclonedx17.PrimitiveXOF, cyclonedx17.PrimitiveKDF,
		cyclonedx17.PrimitiveKeyAgree, cyclonedx17.PrimitiveKEM, cyclonedx17.PrimitiveAE,
		cyclonedx17.PrimitiveCombiner, cyclonedx17.PrimitiveKeyWrap,
		cyclonedx17.PrimitiveOther, cyclonedx17.PrimitiveUnknown,
	}
	for _, v := range want {
		if !validPrimitives[v] {
			t.Errorf("validPrimitives missing %q", v)
		}
	}
}

func TestAssetTypeClosedSet(t *testing.T) {
	want := []string{"algorithm", "certificate", "protocol", "related-crypto-material"}
	for _, v := range want {
		if !validAssetTypes[v] {
			t.Errorf("validAssetTypes missing %q", v)
		}
	}
	// Bug-B canary — library MUST NOT be in the set.
	if validAssetTypes["library"] {
		t.Error("validAssetTypes should NOT contain library; that's the bug we're fixing")
	}
}

func TestValidationTally_RecordAndSummary(t *testing.T) {
	var v validationTally
	v.recordPrimitive("HARDCODED-SECRET")
	v.recordAssetType("library")
	v.recordAssetType("library") // dedupe-by-value not required, but Total counts both
	if v.Total != 3 {
		t.Errorf("Total = %d, want 3", v.Total)
	}
	if v.Primitives != 1 {
		t.Errorf("Primitives = %d, want 1", v.Primitives)
	}
	if v.AssetTypes != 2 {
		t.Errorf("AssetTypes = %d, want 2", v.AssetTypes)
	}
	s := v.Summary()
	if !strings.Contains(s, "3 normalization violation") {
		t.Errorf("Summary = %q, want it to mention 3 violations", s)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd cli && go test ./internal/output/ -run TestPrimitiveClosedSet -v
```

Expected: FAIL with `undefined: validPrimitives` (and similar for the other names).

- [ ] **Step 3: Create the implementation**

`cli/internal/output/validation.go`:
```go
package output

import (
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
)

// validPrimitives is the CycloneDX 1.7 algorithmProperties.primitive closed set.
var validPrimitives = map[cyclonedx17.Primitive]bool{
	cyclonedx17.PrimitiveDRBG: true, cyclonedx17.PrimitiveMAC: true,
	cyclonedx17.PrimitiveBlockCipher: true, cyclonedx17.PrimitiveStreamCipher: true,
	cyclonedx17.PrimitiveSignature: true, cyclonedx17.PrimitiveHash: true,
	cyclonedx17.PrimitivePKE: true, cyclonedx17.PrimitiveXOF: true,
	cyclonedx17.PrimitiveKDF: true, cyclonedx17.PrimitiveKeyAgree: true,
	cyclonedx17.PrimitiveKEM: true, cyclonedx17.PrimitiveAE: true,
	cyclonedx17.PrimitiveCombiner: true, cyclonedx17.PrimitiveKeyWrap: true,
	cyclonedx17.PrimitiveOther: true, cyclonedx17.PrimitiveUnknown: true,
}

// validAssetTypes is the CycloneDX 1.7 cryptoProperties.assetType closed set.
// IMPORTANT: "library" is NOT in this set — see ADR-040.
var validAssetTypes = map[string]bool{
	"algorithm": true, "certificate": true,
	"protocol": true, "related-crypto-material": true,
}

// validModes, validPaddings, validCryptoFunctions, validRelatedMaterialTypes
// follow the same pattern; populated from cli/internal/cyclonedx17/enums.go.
var validModes = map[cyclonedx17.Mode]bool{
	cyclonedx17.ModeCBC: true, cyclonedx17.ModeECB: true, cyclonedx17.ModeCCM: true,
	cyclonedx17.ModeGCM: true, cyclonedx17.ModeCFB: true, cyclonedx17.ModeOFB: true,
	cyclonedx17.ModeCTR: true, cyclonedx17.ModeOther: true, cyclonedx17.ModeUnknown: true,
}

var validPaddings = map[cyclonedx17.Padding]bool{
	cyclonedx17.PaddingPKCS5: true, cyclonedx17.PaddingPKCS7: true,
	cyclonedx17.PaddingPKCS1v15: true, cyclonedx17.PaddingOAEP: true,
	cyclonedx17.PaddingRaw: true, cyclonedx17.PaddingOther: true,
	cyclonedx17.PaddingUnknown: true,
}

var validCryptoFunctions = map[cyclonedx17.CryptoFunction]bool{
	cyclonedx17.CryptoFunctionGenerate: true, cyclonedx17.CryptoFunctionKeygen: true,
	cyclonedx17.CryptoFunctionEncrypt: true, cyclonedx17.CryptoFunctionDecrypt: true,
	cyclonedx17.CryptoFunctionDigest: true, cyclonedx17.CryptoFunctionTag: true,
	cyclonedx17.CryptoFunctionKeyderive: true, cyclonedx17.CryptoFunctionSign: true,
	cyclonedx17.CryptoFunctionVerify: true, cyclonedx17.CryptoFunctionEncapsulate: true,
	cyclonedx17.CryptoFunctionDecapsulate: true, cyclonedx17.CryptoFunctionOther: true,
	cyclonedx17.CryptoFunctionUnknown: true,
}

var validRelatedMaterialTypes = map[cyclonedx17.RelatedCryptoMaterialType]bool{
	cyclonedx17.RelatedCryptoMaterialTypePrivateKey: true,
	cyclonedx17.RelatedCryptoMaterialTypePublicKey: true,
	cyclonedx17.RelatedCryptoMaterialTypeSecretKey: true,
	cyclonedx17.RelatedCryptoMaterialTypeKey: true,
	cyclonedx17.RelatedCryptoMaterialTypeCiphertext: true,
	cyclonedx17.RelatedCryptoMaterialTypeSignature: true,
	cyclonedx17.RelatedCryptoMaterialTypeDigest: true,
	cyclonedx17.RelatedCryptoMaterialTypeInitializationVector: true,
	cyclonedx17.RelatedCryptoMaterialTypeNonce: true,
	cyclonedx17.RelatedCryptoMaterialTypeSeed: true,
	cyclonedx17.RelatedCryptoMaterialTypeSalt: true,
	cyclonedx17.RelatedCryptoMaterialTypeSharedSecret: true,
	cyclonedx17.RelatedCryptoMaterialTypeTag: true,
	cyclonedx17.RelatedCryptoMaterialTypeAdditionalData: true,
	cyclonedx17.RelatedCryptoMaterialTypePassword: true,
	cyclonedx17.RelatedCryptoMaterialTypeCredential: true,
	cyclonedx17.RelatedCryptoMaterialTypeToken: true,
	cyclonedx17.RelatedCryptoMaterialTypeOther: true,
	cyclonedx17.RelatedCryptoMaterialTypeUnknown: true,
}

// maxExamples is how many example violations the tally records for log output.
const maxExamples = 10

// validationTally counts normalization fall-throughs during ConvertScanResult.
// Non-zero values indicate the scanner emitted something outside the CycloneDX 1.7
// closed sets; the converter still produced safe output (PrimitiveOther / etc.)
// but the original value was lost.
type validationTally struct {
	Primitives           int
	AssetTypes           int
	AlgorithmFamilies    int
	Modes                int
	Paddings             int
	CryptoFunctions      int
	RelatedMaterialTypes int
	Total                int
	Examples             []string // first maxExamples violations, formatted "<field>=<value>"
}

func (v *validationTally) record(field, value string) {
	v.Total++
	if len(v.Examples) < maxExamples {
		v.Examples = append(v.Examples, fmt.Sprintf("%s=%q", field, value))
	}
}

func (v *validationTally) recordPrimitive(value string)       { v.Primitives++; v.record("primitive", value) }
func (v *validationTally) recordAssetType(value string)       { v.AssetTypes++; v.record("assetType", value) }
func (v *validationTally) recordAlgorithmFamily(value string) { v.AlgorithmFamilies++; v.record("algorithmFamily", value) }
func (v *validationTally) recordMode(value string)            { v.Modes++; v.record("mode", value) }
func (v *validationTally) recordPadding(value string)         { v.Paddings++; v.record("padding", value) }
func (v *validationTally) recordCryptoFunction(value string)  { v.CryptoFunctions++; v.record("cryptoFunction", value) }
func (v *validationTally) recordMaterialType(value string)    { v.RelatedMaterialTypes++; v.record("relatedCryptoMaterialType", value) }

// Summary returns a single-line stderr summary of violations.
func (v *validationTally) Summary() string {
	if v.Total == 0 {
		return ""
	}
	parts := []string{}
	add := func(label string, n int) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	add("primitive", v.Primitives)
	add("assetType", v.AssetTypes)
	add("algorithmFamily", v.AlgorithmFamilies)
	add("mode", v.Modes)
	add("padding", v.Paddings)
	add("cryptoFunction", v.CryptoFunctions)
	add("relatedCryptoMaterialType", v.RelatedMaterialTypes)
	return fmt.Sprintf("%d normalization violations during CycloneDX 1.7 conversion (%s); examples: %s",
		v.Total, strings.Join(parts, ", "), strings.Join(v.Examples, ", "))
}
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd cli && go test ./internal/output/ -run 'TestPrimitiveClosedSet|TestAssetTypeClosedSet|TestValidationTally_RecordAndSummary' -v
```

Expected: PASS (3 tests).

- [ ] **Step 5: Commit (deferred to end of Phase 1)**

Phase 1 commits as one logical unit. Don't commit yet — proceed to Task 1.2.

---

### Task 1.2: Fix Bug A — AlgorithmPrimitive bypass + reroute HARDCODED-SECRET

**Files:**
- Modify: `cli/internal/output/converter.go:487-491` (the bypass site)
- Modify: `cli/internal/output/converter.go:446-477` (`convertCryptoProperties` — hook reroute before the assetType switch)
- Test: `cli/internal/output/converter_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cli/internal/output/converter_test.go`:
```go
func TestConvertFinding_HardcodedSecretReroute(t *testing.T) {
	f := &types.Finding{
		ID:        "test-hc-1",
		Name:      "hardcoded API key",
		AssetType: types.AssetAlgorithm, // scanner currently emits this
		Properties: types.CryptoProperties{
			AlgorithmPrimitive: "HARDCODED-SECRET",
		},
	}
	comp := convertFinding(f)

	if comp.CryptoProperties == nil {
		t.Fatal("CryptoProperties is nil")
	}
	if comp.CryptoProperties.AssetType != "related-crypto-material" {
		t.Errorf("AssetType = %q, want related-crypto-material (rerouted)",
			comp.CryptoProperties.AssetType)
	}
	if comp.CryptoProperties.AlgorithmProperties != nil {
		t.Error("AlgorithmProperties should be nil after reroute")
	}
	if comp.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		t.Fatal("RelatedCryptoMaterialProperties is nil")
	}
	if comp.CryptoProperties.RelatedCryptoMaterialProperties.Type != cyclonedx17.RelatedCryptoMaterialTypeOther {
		// CycloneDX 1.7 has no "secret-parameter" — see the enum in
		// cli/internal/cyclonedx17/enums.go. Closest valid bucket for an
		// observed hardcoded secret string is "other" (or "credential" /
		// "token" / "password" depending on naming heuristics).
		// Implementation picks the closest match; this test pins "other"
		// as the safe default.
		t.Errorf("MaterialType = %q, want other", comp.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	}
}

func TestConvertAlgorithmProperties_KnownCanonicalToken(t *testing.T) {
	// AlgorithmPrimitive set to a canonical algorithm token should derive the
	// correct primitive (hash for MD5, block-cipher for AES) — not pass through
	// the raw token.
	for _, tc := range []struct {
		name      string
		token     string
		wantPrim  cyclonedx17.Primitive
	}{
		{"MD5 → hash", "MD5", cyclonedx17.PrimitiveHash},
		{"AES-256-GCM → block-cipher", "AES-256-GCM", cyclonedx17.PrimitiveBlockCipher},
		{"unknown → other", "WAT-1234", cyclonedx17.PrimitiveOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := convertAlgorithmProperties(&types.CryptoProperties{
				AlgorithmPrimitive: tc.token,
			})
			if ap.Primitive != tc.wantPrim {
				t.Errorf("Primitive = %q, want %q", ap.Primitive, tc.wantPrim)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd cli && go test ./internal/output/ -run 'TestConvertFinding_HardcodedSecretReroute|TestConvertAlgorithmProperties_KnownCanonicalToken' -v
```

Expected: FAIL — HARDCODED-SECRET passes through, MD5 isn't mapped to hash.

- [ ] **Step 3: Add the token→primitive map**

Add to `cli/internal/output/converter.go` near the existing maps (after `primitiveMap`, line ~277):
```go
// canonicalTokenPrimitive maps canonical algorithm tokens (as emitted by
// OpenGrep rule cbom-primitive metadata) to their CycloneDX 1.7 primitive.
// Used by convertAlgorithmProperties when AlgorithmPrimitive is a known
// algorithm name rather than a primitive name.
var canonicalTokenPrimitive = map[string]cyclonedx17.Primitive{
	// hash family
	"MD2": cyclonedx17.PrimitiveHash, "MD4": cyclonedx17.PrimitiveHash, "MD5": cyclonedx17.PrimitiveHash,
	"SHA-1": cyclonedx17.PrimitiveHash, "SHA-2": cyclonedx17.PrimitiveHash, "SHA-3": cyclonedx17.PrimitiveHash,
	"SHA1": cyclonedx17.PrimitiveHash, "SHA256": cyclonedx17.PrimitiveHash, "SHA384": cyclonedx17.PrimitiveHash,
	"SHA512": cyclonedx17.PrimitiveHash, "SHA-224": cyclonedx17.PrimitiveHash, "SHA-256": cyclonedx17.PrimitiveHash,
	"SHA-384": cyclonedx17.PrimitiveHash, "SHA-512": cyclonedx17.PrimitiveHash,
	"BLAKE2": cyclonedx17.PrimitiveHash, "BLAKE3": cyclonedx17.PrimitiveHash,
	"RIPEMD": cyclonedx17.PrimitiveHash, "Whirlpool": cyclonedx17.PrimitiveHash,
	// block-cipher
	"AES": cyclonedx17.PrimitiveBlockCipher, "AES-128": cyclonedx17.PrimitiveBlockCipher,
	"AES-192": cyclonedx17.PrimitiveBlockCipher, "AES-256": cyclonedx17.PrimitiveBlockCipher,
	"AES-128-GCM": cyclonedx17.PrimitiveBlockCipher, "AES-256-GCM": cyclonedx17.PrimitiveBlockCipher,
	"AES-128-CBC": cyclonedx17.PrimitiveBlockCipher, "AES-256-CBC": cyclonedx17.PrimitiveBlockCipher,
	"DES": cyclonedx17.PrimitiveBlockCipher, "3DES": cyclonedx17.PrimitiveBlockCipher,
	"Blowfish": cyclonedx17.PrimitiveBlockCipher, "Twofish": cyclonedx17.PrimitiveBlockCipher,
	"CAMELLIA": cyclonedx17.PrimitiveBlockCipher, "ARIA": cyclonedx17.PrimitiveBlockCipher,
	"SEED": cyclonedx17.PrimitiveBlockCipher, "SM4": cyclonedx17.PrimitiveBlockCipher,
	"IDEA": cyclonedx17.PrimitiveBlockCipher, "CAST5": cyclonedx17.PrimitiveBlockCipher,
	"CAST6": cyclonedx17.PrimitiveBlockCipher, "Serpent": cyclonedx17.PrimitiveBlockCipher,
	"Skipjack": cyclonedx17.PrimitiveBlockCipher,
	// stream-cipher
	"ChaCha20": cyclonedx17.PrimitiveStreamCipher, "ChaCha": cyclonedx17.PrimitiveStreamCipher,
	"Salsa20": cyclonedx17.PrimitiveStreamCipher, "RC4": cyclonedx17.PrimitiveStreamCipher,
	// signature
	"RSA": cyclonedx17.PrimitiveSignature, "DSA": cyclonedx17.PrimitiveSignature,
	"ECDSA": cyclonedx17.PrimitiveSignature, "EdDSA": cyclonedx17.PrimitiveSignature,
	"Ed25519": cyclonedx17.PrimitiveSignature, "Ed448": cyclonedx17.PrimitiveSignature,
	"ML-DSA": cyclonedx17.PrimitiveSignature, "SLH-DSA": cyclonedx17.PrimitiveSignature,
	// key-agree
	"DH": cyclonedx17.PrimitiveKeyAgree, "ECDH": cyclonedx17.PrimitiveKeyAgree,
	"X25519": cyclonedx17.PrimitiveKeyAgree, "X448": cyclonedx17.PrimitiveKeyAgree,
	// kem
	"ML-KEM": cyclonedx17.PrimitiveKEM, "BIKE": cyclonedx17.PrimitiveKEM, "HQC": cyclonedx17.PrimitiveKEM,
	// kdf
	"HKDF": cyclonedx17.PrimitiveKDF, "PBKDF1": cyclonedx17.PrimitiveKDF, "PBKDF2": cyclonedx17.PrimitiveKDF,
	"scrypt": cyclonedx17.PrimitiveKDF, "bcrypt": cyclonedx17.PrimitiveKDF, "Argon2": cyclonedx17.PrimitiveKDF,
	// mac
	"HMAC": cyclonedx17.PrimitiveMAC, "CMAC": cyclonedx17.PrimitiveMAC, "KMAC": cyclonedx17.PrimitiveMAC,
	"Poly1305": cyclonedx17.PrimitiveMAC,
}

// rerouteMarker identifies AlgorithmPrimitive tokens that indicate the finding
// should be modeled as a different assetType. Returns the target assetType and
// material type (when applicable). Empty assetType means no reroute needed.
func rerouteMarker(token string) (assetType types.AssetType, materialType string) {
	switch strings.ToUpper(token) {
	case "HARDCODED-SECRET", "HARDCODE-SECRET", "HARDCODED_SECRET":
		return types.AssetRelatedCryptoMaterial, "other"
	case "PRIVATE-KEY-PEM", "PRIVATE-KEY", "PRIVATE_KEY":
		return types.AssetRelatedCryptoMaterial, "private-key"
	case "PUBLIC-KEY-PEM", "PUBLIC-KEY", "PUBLIC_KEY":
		return types.AssetRelatedCryptoMaterial, "public-key"
	case "CRYPTO-LIBRARY-IMPORT":
		// Library detection — handled by Task 1.3 (assetType="library"
		// at the finding level). This path is only hit when scanner sets
		// AlgorithmPrimitive but leaves AssetType=algorithm; we return
		// empty to fall through to algorithm handling. The library reroute
		// in Task 1.3 takes precedence when AssetType=="library".
		return "", ""
	}
	return "", ""
}
```

- [ ] **Step 4: Update `convertCryptoProperties` to call the reroute**

Replace lines 446-477 of `converter.go` with:
```go
// convertCryptoProperties builds CycloneDX 1.7 cryptoProperties from a Finding,
// applying AlgorithmPrimitive-token reroutes (HARDCODED-SECRET → related-crypto-material, etc.)
// before the assetType switch. Records violations in tally if non-nil.
func convertCryptoProperties(f *types.Finding, tally *validationTally) *cyclonedx17.CryptoProperties {
	props := &f.Properties

	// Reroute by AlgorithmPrimitive marker (Bug A fix).
	effectiveAssetType := f.AssetType
	rerouteMaterial := ""
	if props.AlgorithmPrimitive != "" {
		if at, mt := rerouteMarker(props.AlgorithmPrimitive); at != "" {
			effectiveAssetType = at
			rerouteMaterial = mt
		}
	}

	cp := &cyclonedx17.CryptoProperties{
		AssetType: string(effectiveAssetType),
	}

	switch effectiveAssetType {
	case types.AssetAlgorithm:
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	case types.AssetProtocol:
		cp.ProtocolProperties = convertProtocolProperties(props)
	case types.AssetCertificate:
		cp.CertificateProperties = convertCertificateProperties(props)
	case types.AssetRelatedCryptoMaterial:
		if rerouteMaterial != "" {
			// Reroute case: clear primitive (it was the marker) and set material type.
			cp.RelatedCryptoMaterialProperties = &cyclonedx17.RelatedCryptoMaterialProperties{
				Type: normalizeRelatedCryptoMaterialType(rerouteMaterial),
			}
			// Do NOT populate AlgorithmProperties on a rerouted finding.
		} else {
			cp.RelatedCryptoMaterialProperties = convertRelatedCryptoMaterialProperties(props)
			// Preserve existing dual-properties behavior for non-rerouted material findings.
			if props.AlgorithmPrimitive != "" {
				cp.AlgorithmProperties = convertAlgorithmProperties(props)
			}
		}
	default:
		// Unknown assetType — record violation and emit "other"-ish output.
		if tally != nil {
			tally.recordAssetType(string(effectiveAssetType))
		}
		cp.AssetType = "algorithm" // safest default to keep downstream consumers happy
		cp.AlgorithmProperties = convertAlgorithmProperties(props)
	}

	return cp
}
```

- [ ] **Step 5: Update `convertAlgorithmProperties` to use canonical-token map**

Replace lines 487-515 with:
```go
func convertAlgorithmProperties(p *types.CryptoProperties) *cyclonedx17.AlgorithmProperties {
	primitive := normalizePrimitive(p.Primitive)
	if p.AlgorithmPrimitive != "" {
		// First check the canonical-token map (handles MD5, AES-256-GCM, etc.).
		if cp, ok := canonicalTokenPrimitive[strings.ToUpper(p.AlgorithmPrimitive)]; ok {
			primitive = cp
		} else if cp, ok := canonicalTokenPrimitive[p.AlgorithmPrimitive]; ok {
			primitive = cp
		} else {
			// Unknown token — try as a primitive name, else default to "other".
			lower := strings.ToLower(strings.TrimSpace(p.AlgorithmPrimitive))
			if cp, ok := primitiveMap[lower]; ok {
				primitive = cp
			} else {
				primitive = cyclonedx17.PrimitiveOther
			}
		}
	}
	ap := &cyclonedx17.AlgorithmProperties{
		Primitive:                primitive,
		AlgorithmFamily:          normalizeAlgorithmFamily(p.AlgorithmFamily),
		Mode:                     normalizeMode(p.Mode),
		Padding:                  normalizePadding(p.Padding),
		ClassicalSecurityLevel:   p.ClassicalSecurity,
		NistQuantumSecurityLevel: p.NistQuantumLevel,
	}
	if ap.ClassicalSecurityLevel == 0 && p.KeySize > 0 {
		ap.ClassicalSecurityLevel = p.KeySize
	}
	if len(p.CryptoFunctions) > 0 {
		funcs := make([]cyclonedx17.CryptoFunction, 0, len(p.CryptoFunctions))
		for _, fn := range p.CryptoFunctions {
			funcs = append(funcs, normalizeCryptoFunction(fn))
		}
		ap.CryptoFunctions = funcs
	}
	return ap
}
```

- [ ] **Step 6: Update `convertFinding` to pass tally**

Replace lines 399-422 (`convertFinding`):
```go
func convertFinding(f *types.Finding) Component {
	return convertFindingTally(f, nil)
}

func convertFindingTally(f *types.Finding, tally *validationTally) Component {
	comp := Component{
		Type:        "cryptographic-asset",
		BOMRef:      f.ID,
		Name:        f.Name,
		Description: f.Description,
		Evidence: &Evidence{
			Occurrences: []Occurrence{
				{Location: f.Location.File, Line: f.Location.StartLine},
			},
		},
	}
	cp := convertCryptoProperties(f, tally)
	comp.CryptoProperties = cp
	comp.Properties = buildFindingProperties(f)
	return comp
}
```

- [ ] **Step 7: Run tests to verify pass**

```bash
cd cli && go test ./internal/output/ -run 'TestConvertFinding_HardcodedSecretReroute|TestConvertAlgorithmProperties_KnownCanonicalToken' -v
```

Expected: PASS.

- [ ] **Step 8: Run full converter tests to ensure no regression**

```bash
cd cli && go test ./internal/output/ -count=1
```

Expected: PASS. If any existing tests broke, they probably expected the old bypass behavior — update those tests to use the new semantics.

---

### Task 1.3: Fix Bug B — `library` assetType → CycloneDX `type: library` component

**Files:**
- Modify: `cli/internal/output/converter.go` (`convertFindingTally`)
- Test: `cli/internal/output/converter_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cli/internal/output/converter_test.go`:
```go
func TestConvertFinding_LibraryAssetType_EmitsLibraryComponent(t *testing.T) {
	f := &types.Finding{
		ID:        "test-lib-1",
		Name:      "openssl",
		AssetType: types.AssetType("library"), // bug source: opengrep cbom-library-import rule
		Properties: types.CryptoProperties{
			AlgorithmPrimitive: "CRYPTO-LIBRARY-IMPORT",
		},
		Location: types.Location{File: "requirements.txt", StartLine: 4},
	}
	var tally validationTally
	comp := convertFindingTally(f, &tally)

	if comp.Type != "library" {
		t.Errorf("Type = %q, want library (per ADR-040)", comp.Type)
	}
	if comp.CryptoProperties != nil {
		t.Errorf("CryptoProperties should be nil for library components, got %+v", comp.CryptoProperties)
	}
	if comp.Name != "openssl" {
		t.Errorf("Name = %q, want openssl", comp.Name)
	}
	// Library findings do NOT count as a validation violation — they take a
	// designed path, not a fall-through.
	if tally.Total != 0 {
		t.Errorf("Total = %d, want 0 (library is designed path, not violation)", tally.Total)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd cli && go test ./internal/output/ -run TestConvertFinding_LibraryAssetType_EmitsLibraryComponent -v
```

Expected: FAIL — Type is "cryptographic-asset", CryptoProperties is non-nil.

- [ ] **Step 3: Add the library-component branch in `convertFindingTally`**

Update `convertFindingTally` in `cli/internal/output/converter.go`:
```go
func convertFindingTally(f *types.Finding, tally *validationTally) Component {
	// ADR-040: library findings (from opengrep cbom-library-import rules and
	// yara-x library signatures) emit as regular CycloneDX components with
	// type: library, no cryptoProperties. They are not cryptographic assets.
	if string(f.AssetType) == "library" {
		return Component{
			Type:        "library",
			BOMRef:      f.ID,
			Name:        f.Name,
			Description: f.Description,
			Evidence: &Evidence{
				Occurrences: []Occurrence{
					{Location: f.Location.File, Line: f.Location.StartLine},
				},
			},
			Properties: buildFindingProperties(f),
		}
	}

	comp := Component{
		Type:        "cryptographic-asset",
		BOMRef:      f.ID,
		Name:        f.Name,
		Description: f.Description,
		Evidence: &Evidence{
			Occurrences: []Occurrence{
				{Location: f.Location.File, Line: f.Location.StartLine},
			},
		},
	}
	cp := convertCryptoProperties(f, tally)
	comp.CryptoProperties = cp
	comp.Properties = buildFindingProperties(f)
	return comp
}
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd cli && go test ./internal/output/ -run TestConvertFinding_LibraryAssetType -v
```

Expected: PASS.

- [ ] **Step 5: Run full converter tests + JSON output tests**

```bash
cd cli && go test ./internal/output/ -count=1 -v -run 'TestConvert|TestCycloneDX'
```

Expected: PASS. Library findings now produce schema-valid components.

---

### Task 1.4: Wire validationTally through `ConvertScanResult`

**Files:**
- Modify: `cli/internal/output/converter.go` (`ConvertScanResult`)
- Test: `cli/internal/output/converter_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestConvertScanResult_TallyAccumulates(t *testing.T) {
	result := &types.ScanResult{
		Target: "/tmp/x",
		Findings: []types.Finding{
			{ID: "1", AssetType: types.AssetAlgorithm, Properties: types.CryptoProperties{AlgorithmPrimitive: "HARDCODED-SECRET"}},
			{ID: "2", AssetType: types.AssetType("library"), Name: "openssl"},
			{ID: "3", AssetType: types.AssetType("WAT")}, // unknown assetType → violation
		},
	}
	_, tally := ConvertScanResultWithTally(result)
	// HARDCODED-SECRET reroutes cleanly (no violation), library uses designed
	// path (no violation), WAT is the only true unknown.
	if tally.Total != 1 {
		t.Errorf("Total = %d, want 1 (only WAT assetType is unknown)", tally.Total)
	}
	if tally.AssetTypes != 1 {
		t.Errorf("AssetTypes = %d, want 1", tally.AssetTypes)
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/output/ -run TestConvertScanResult_TallyAccumulates -v
```

Expected: FAIL — `undefined: ConvertScanResultWithTally`.

- [ ] **Step 3: Add the new public function**

Add to `cli/internal/output/converter.go` (right after `ConvertScanResult`):
```go
// ConvertScanResultWithTally is like ConvertScanResult but also returns a
// validationTally counting normalization fall-throughs. Callers that want
// to surface or fail on tally totals (e.g. --strict-validate) use this.
func ConvertScanResultWithTally(result *types.ScanResult) (*BOM, validationTally) {
	var tally validationTally
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		Version:      1,
		SerialNumber: generateUUID4(),
		Metadata: &Metadata{
			Timestamp: result.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			Tools: []Tool{{Name: "CipherRadar", Version: AppVersion, Vendor: "nk-sentinel"}},
		},
	}
	components := make([]Component, 0, len(result.Findings))
	for i := range result.Findings {
		components = append(components, convertFindingTally(&result.Findings[i], &tally))
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})
	bom.Components = components
	return bom, tally
}
```

Keep the existing `ConvertScanResult` as a thin wrapper:
```go
func ConvertScanResult(result *types.ScanResult) *BOM {
	bom, _ := ConvertScanResultWithTally(result)
	return bom
}
```

- [ ] **Step 4: Run + verify pass**

```bash
cd cli && go test ./internal/output/ -run TestConvertScanResult_TallyAccumulates -v
```

Expected: PASS.

---

### Task 1.5: Add `--strict-validate` flag + tally warning emission

**Files:**
- Modify: `cli/internal/cmd/scan.go` (flag declaration + use in scan execution)
- Test: `cli/internal/cmd/scan_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cli/internal/cmd/scan_test.go`:
```go
func TestScan_StrictValidate_FailsOnViolation(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a fixture that will trigger an unknown assetType violation.
	// Easiest: a YAML/python config that produces a HARDCODED-SECRET (rerouted, no violation)
	// is not enough — we need an actual unknown enum value. Use the contrived path:
	// invoke ConvertScanResult on a result containing an unknown assetType, then run
	// the strict check. Since this is integration-level, we exercise via the scan command.
	//
	// Strategy: write a minimal test that asserts the --strict-validate FLAG is
	// recognized and propagates. End-to-end integration via real findings is covered
	// in the regression smoke test (Task 1.7).
	cmd := newScanCmd()
	cmd.SetArgs([]string{tmpDir, "--strict-validate", "--format", "cyclonedx-json"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		// Empty dir → 0 findings → 0 violations → should succeed.
		t.Errorf("--strict-validate on empty dir should succeed, got: %v", err)
	}
}
```

(If `newScanCmd` doesn't exist, refactor the existing init pattern to expose it. Use whatever helper the existing tests use — check `cli/internal/cmd/scan_test.go` for the pattern.)

- [ ] **Step 2: Run + verify failure or skip**

```bash
cd cli && go test ./internal/cmd/ -run TestScan_StrictValidate -v
```

Expected: FAIL — `--strict-validate` is an unknown flag.

- [ ] **Step 3: Add the flag declaration**

In `cli/internal/cmd/scan.go`, after the existing flag declarations (around line 48):
```go
scanCmd.Flags().Bool("strict-validate", false,
    "fail the scan if any output value falls outside the CycloneDX 1.7 enum closed sets (default: warn only)")
```

- [ ] **Step 4: Read flag + wire to tally check**

In the scan execution body of `cli/internal/cmd/scan.go`, after `result` is built and before `writeOutputs` is called (around line 285):
```go
strictValidate, _ := cmd.Flags().GetBool("strict-validate")

// Compute CycloneDX BOM once with tally so we can surface violations
// regardless of which output format is requested. Reused by writers below.
_, validationTallyResult := output.ConvertScanResultWithTally(result)
if validationTallyResult.Total > 0 {
    fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s\n", validationTallyResult.Summary())
    if strictValidate {
        return fmt.Errorf("strict-validate: %d normalization violation(s); see warnings above", validationTallyResult.Total)
    }
}
```

(Note: this re-runs conversion. For commits 3+, when we restructure, we can cache the BOM. For now, double-convert is acceptable — convert is O(n) over findings.)

- [ ] **Step 5: Run + verify pass**

```bash
cd cli && go test ./internal/cmd/ -run TestScan_StrictValidate -v
```

Expected: PASS.

- [ ] **Step 6: Manual smoke**

```bash
cd cli && go build -o /tmp/cradar-c1 ./cmd/cradar
/tmp/cradar-c1 scan ../scanner/rules/python/ --strict-validate --format cyclonedx-json --output /tmp/strict-test.json 2>&1 | head -20
```

Expected: exit 0 (assuming current scanner output produces no violations after Task 1.2-1.3 fixes). If non-zero, inspect stderr for the violation summary.

---

### Task 1.6: Fix at source — `config_scanner.go` emits material directly

**Files:**
- Modify: `cli/internal/scanner/config/config_scanner.go:122,189`
- Modify: `cli/internal/scanner/config/config_scanner_test.go:283,312`

- [ ] **Step 1: Read current scanner code**

```bash
cd /home/nk-sentinel/projects/cradar-cbom-export-quality
sed -n '115,130p;185,195p' cli/internal/scanner/config/config_scanner.go
```

Note the surrounding context (which Finding fields are set together with `AlgorithmPrimitive: "HARDCODED-SECRET"`).

- [ ] **Step 2: Update the scanner to emit material directly**

For both occurrences (lines 122 and 189), replace:
```go
AlgorithmPrimitive: "HARDCODED-SECRET",
```
with:
```go
// Hardcoded secret — model as related-crypto-material per ADR-040.
// (Was: AlgorithmPrimitive: "HARDCODED-SECRET" — leaked into cyclonedx
// algorithmProperties.primitive enum; defense-in-depth, converter also
// reroutes this if scanners regress.)
MaterialType: "other",
```

And change the surrounding `AssetType: types.AssetAlgorithm` (or whatever is currently set on that Finding literal) to:
```go
AssetType: types.AssetRelatedCryptoMaterial,
```

- [ ] **Step 3: Update the scanner tests to match**

In `cli/internal/scanner/config/config_scanner_test.go` lines 283 and 312, replace:
```go
if f.Properties.AlgorithmPrimitive != "HARDCODED-SECRET" {
    t.Errorf("%s: want AlgorithmPrimitive=HARDCODED-SECRET, got %q", ...)
}
```
with:
```go
if f.AssetType != types.AssetRelatedCryptoMaterial {
    t.Errorf("%s: want AssetType=related-crypto-material, got %q", tc.name, f.AssetType)
}
if f.Properties.MaterialType != "other" {
    t.Errorf("%s: want MaterialType=other, got %q", tc.name, f.Properties.MaterialType)
}
```

- [ ] **Step 4: Run the scanner tests**

```bash
cd cli && go test ./internal/scanner/config/ -v
```

Expected: PASS.

---

### Task 1.7: Doc — ADR-040 + update TODO-SCHEMA-VALIDATION

**Files:**
- Create: `docs/decisions/ADR-040-library-asset-type.md`
- Modify: `docs/decisions/DECISION-LOG.md` (append entry)
- Modify: `docs/benchmark/TODO-SCHEMA-VALIDATION.md` (mark resolved)

- [ ] **Step 1: Write ADR-040**

`docs/decisions/ADR-040-library-asset-type.md`:
```markdown
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
```

- [ ] **Step 2: Append DECISION-LOG entry**

Append to `docs/decisions/DECISION-LOG.md`:
```markdown

## 2026-05-25 — ADR-040: Library detections emit as type=library components

OpenGrep + YARA-X library-presence findings (cbom-asset-type: library) no longer pass
the invalid value through to CycloneDX `cryptoProperties.assetType`. Routed to
component `type: library` per CycloneDX 1.7 spec. Breaking change for CBOM JSON consumers
that read `assetType: "library"`. See ADR-040.
```

- [ ] **Step 3: Update TODO-SCHEMA-VALIDATION.md to mark resolved**

Replace contents of `docs/benchmark/TODO-SCHEMA-VALIDATION.md` with:
```markdown
# RESOLVED: CycloneDX 1.7 Schema Validation Errors

**Status:** Resolved 2026-05-25
**Resolved by:** feature/cbom-export-quality, commit 1 (see `docs/superpowers/specs/2026-05-25-cbom-export-quality-design.md`)

## History

Originally filed 2026-03-23 with 37 enum-validation failures across `algorithmFamily`,
`cryptoFunctions`, `mode`, `padding`. All 37 were resolved by the normalization maps
in `cli/internal/output/converter.go` (lines 15-297) before this commit landed.

Two additional bugs were discovered during the 2026-05-25 audit:
- **AlgorithmPrimitive bypass** — `HARDCODED-SECRET` (from `config_scanner.go`) and
  `CRYPTO-LIBRARY-IMPORT` (from OpenGrep rules) were cast straight to
  `cyclonedx17.Primitive` without normalization. Fixed in `convertCryptoProperties`
  with a `rerouteMarker` switch + `canonicalTokenPrimitive` map.
- **library assetType** — emitted as-is from OpenGrep inventory rules; not in
  CycloneDX 1.7 enum. Fixed per ADR-040 (emit as `type: library` component).

## Preventing regressions

`--strict-validate` flag (added in this commit) fails the scan if the
`validationTally` registers any non-zero fall-through during CycloneDX conversion.
Default behavior warns to stderr; CI should run with `--strict-validate`.
```

(Do not delete the file — preserve as audit trail per spec.)

---

### Task 1.8: Phase 1 regression gate + commit

- [ ] **Step 1: Full test sweep**

```bash
cd cli && go test ./... -count=1
```

Expected: ALL PASS.

- [ ] **Step 2: Lint + vet**

```bash
cd cli && go vet ./... && golangci-lint run
```

Expected: clean (no findings).

- [ ] **Step 3: Schema-validate smoke test**

```bash
cd cli && go build -o /tmp/cradar-c1 ./cmd/cradar
/tmp/cradar-c1 scan ../scanner/rules/python/ \
    --format cyclonedx-json --output /tmp/c1-validate.json --validate 2>&1 | tail -5
```

Expected: `CycloneDX 1.7 schema validation PASSED` on stderr; exit 0.

If FAIL: inspect the schema errors, identify which converter path is leaking, add to the alias maps or canonical-token map.

- [ ] **Step 4: Baseline diff (intended-only changes)**

```bash
/tmp/cradar-c1 scan /home/nk-sentinel/projects/cradar-cbom-export-quality/scanner/rules/python/ \
    --format cyclonedx-json --output /tmp/c1-output.json 2>/dev/null
diff <(jq -S 'del(.serialNumber, .metadata.timestamp)' /tmp/cbom-baseline/python.json) \
     <(jq -S 'del(.serialNumber, .metadata.timestamp)' /tmp/c1-output.json) | head -40
```

Expected: differences only in:
- Components where `assetType` was `library` → now `type: library`
- Components where `primitive` was `HARDCODED-SECRET` → now rerouted to related-crypto-material with material type `other`

No other unintended changes.

- [ ] **Step 5: Commit**

```bash
cd /home/nk-sentinel/projects/cradar-cbom-export-quality
git add cli/internal/output/converter.go \
        cli/internal/output/converter_test.go \
        cli/internal/output/validation.go \
        cli/internal/output/validation_test.go \
        cli/internal/cmd/scan.go \
        cli/internal/cmd/scan_test.go \
        cli/internal/scanner/config/config_scanner.go \
        cli/internal/scanner/config/config_scanner_test.go \
        docs/decisions/ADR-040-library-asset-type.md \
        docs/decisions/DECISION-LOG.md \
        docs/benchmark/TODO-SCHEMA-VALIDATION.md
git commit -m "feat(converter): close cyclonedx 1.7 enum gaps + add strict validation

Fix two bleed-through bugs introduced by scanner metadata:
- AlgorithmPrimitive bypass passed HARDCODED-SECRET, CRYPTO-LIBRARY-IMPORT
  straight to cyclonedx primitive enum; now normalized + rerouted.
- library asset_type from opengrep inventory rules (and yarax starter
  rules) had no cyclonedx 1.7 home; now emitted as type:library component
  without cryptoProperties per ADR-040.

Adds validationTally + --strict-validate flag so future bleed-through
is visible (default warn, opt-in fail)."
```

---

# Phase 2 — Quantum Readiness Expansion (Commit 2)

**Goal:** Move quantum table from inline Go map to embedded YAML, expand ~30 → ~80 entries, add `QuantumNotApplicable` for non-algorithm asset types, add `normalizeFamily` for fuzzy name matching.

**End-state commit message:**
```
feat(quantum): expand readiness table to ~80 algorithms via embedded yaml

Move algorithm classification from inline Go map to
cli/internal/scanner/quantum/quantum-readiness.yml. Adds full PQC
suite (ML-KEM, ML-DSA, SLH-DSA, Falcon→FN-DSA, XMSS, LMS, BIKE, HQC,
FrodoKEM) with silent canonical mapping for deprecated names (Kyber→ML-KEM,
Dilithium→ML-DSA, SPHINCS+→SLH-DSA). Adds classical gaps (ElGamal, ECIES,
KMAC, all HMAC/HKDF/PBKDF2 variants, password hashers).

normalizeFamily strips -<size>(-<mode>)? suffix so RSA-2048 / aes-128-gcm
match family root. New QuantumNotApplicable status omits quantum field
for certificates / hardcoded secrets / library findings.
```

### Task 2.1: Add `QuantumNotApplicable` type

**Files:**
- Modify: `cli/internal/types/enums.go:90-101`
- Test: `cli/internal/types/types_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cli/internal/types/types_test.go`:
```go
func TestQuantumNotApplicable(t *testing.T) {
	if QuantumNotApplicable != "not-applicable" {
		t.Errorf("QuantumNotApplicable = %q, want not-applicable", QuantumNotApplicable)
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/types/ -run TestQuantumNotApplicable -v
```

Expected: FAIL — `undefined: QuantumNotApplicable`.

- [ ] **Step 3: Add the constant**

In `cli/internal/types/enums.go`, after `Broken QuantumStatus = "broken"` (line 101):
```go
// QuantumNotApplicable indicates the asset is not an algorithm (e.g. a
// certificate, hardcoded secret, or library detection) and the quantum
// readiness lookup should be skipped entirely. Output writers should omit
// the quantum status field rather than render "Unknown".
QuantumNotApplicable QuantumStatus = "not-applicable"
```

- [ ] **Step 4: Run + verify pass**

```bash
cd cli && go test ./internal/types/ -run TestQuantumNotApplicable -v
```

Expected: PASS.

---

### Task 2.2: Create initial YAML table

**Files:**
- Create: `cli/internal/scanner/quantum/quantum-readiness.yml`
- Test: `cli/internal/scanner/quantum/quantum_yaml_test.go`

- [ ] **Step 1: Write the failing YAML round-trip test**

`cli/internal/scanner/quantum/quantum_yaml_test.go`:
```go
package quantum

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestYAML_LoadsAtPackageInit(t *testing.T) {
	if len(table) < 70 {
		t.Errorf("table has %d entries, want >= 70 (per spec target ~80)", len(table))
	}
	// Spot-check critical entries.
	for _, fam := range []string{"rsa", "aes", "md5", "sha-256", "ml-kem", "ml-dsa", "slh-dsa"} {
		if _, ok := table[fam]; !ok {
			t.Errorf("table missing critical family: %q", fam)
		}
	}
}

func TestYAML_AliasesResolveToCanonical(t *testing.T) {
	for _, tc := range []struct{ alias, canonical string }{
		{"kyber", "ml-kem"}, {"kyber-512", "ml-kem"},
		{"dilithium", "ml-dsa"}, {"sphincs+", "slh-dsa"},
		{"falcon", "fn-dsa"},
	} {
		info := GetInfo(tc.alias)
		canonInfo := GetInfo(tc.canonical)
		if info.Status != canonInfo.Status {
			t.Errorf("alias %q status = %q, canonical %q status = %q (should match)",
				tc.alias, info.Status, tc.canonical, canonInfo.Status)
		}
	}
}

func TestYAML_NonAlgorithmAssetTypeSkips(t *testing.T) {
	info := GetInfoForAsset("openssl", "library")
	if info.Status != types.QuantumNotApplicable {
		t.Errorf("Status = %q, want not-applicable for library asset type", info.Status)
	}
	info = GetInfoForAsset("server-cert", "certificate")
	if info.Status != types.QuantumNotApplicable {
		t.Errorf("Status = %q, want not-applicable for certificate", info.Status)
	}
}

func TestNormalizeFamily(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"RSA-2048", "rsa"}, {"aes-128-gcm", "aes"}, {"ECDSA-P256", "ecdsa"},
		{"sha-256", "sha-256"}, {"sha3-512", "sha3-512"},
		{"", ""}, {"NotAlgorithm123", "notalgorithm"},
	} {
		got := normalizeFamily(tc.in)
		if got != tc.out {
			t.Errorf("normalizeFamily(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestYAMLLastUpdatedComment(t *testing.T) {
	if !strings.Contains(string(quantumYAML), "# Last updated:") {
		t.Error("quantum-readiness.yml should carry a Last updated: comment")
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/scanner/quantum/ -v
```

Expected: FAIL — many undefined symbols (`quantumYAML`, `GetInfoForAsset`, `normalizeFamily`, table is too small, etc.).

- [ ] **Step 3: Write the YAML data file**

`cli/internal/scanner/quantum/quantum-readiness.yml`:
```yaml
# CipherRadar quantum-readiness table
# Last updated: 2026-05-25
# Each algorithm has a canonical `family` (always lowercase, used as map key).
# `aliases` are silently mapped to the canonical family (Kyber → ML-KEM, etc).
# `status`: quantum-vulnerable | quantum-safe | quantum-unknown | broken
# `nist_level`: 0 (not applicable) or 1/3/5 (NIST PQC security categories)
# `recommendation`: short migration guidance; appears in PDF + text output

version: 1
non_algorithm_asset_types:
  - related-crypto-material
  - certificate
  - library

algorithms:
  # ── Quantum-vulnerable (Shor's algorithm breaks these) ──
  - family: rsa
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM (encryption) or ML-DSA (signatures)"
    aliases: [rsa-pss, rsa-oaep, rsaes-pkcs1, rsassa-pkcs1, rsassa-pss]
  - family: dsa
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-DSA"
  - family: dh
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM"
    aliases: [ffdh, diffie-hellman]
  - family: ecdsa
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-DSA"
  - family: ecdh
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM"
  - family: ec
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM (key agreement) or ML-DSA (signatures)"
  - family: ed25519
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-DSA"
  - family: ed448
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-DSA"
  - family: x25519
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM"
  - family: x448
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM"
  - family: elgamal
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM"
  - family: ecies
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM + symmetric cipher composition"
  - family: sm2
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-DSA"
  - family: gost
    status: quantum-vulnerable
    nist_level: 0
    recommendation: "Migrate to ML-KEM / ML-DSA"

  # ── Quantum-safe symmetric (Grover halves effective key size) ──
  - family: aes
    status: quantum-safe
    nist_level: 1
    recommendation: "AES is quantum-safe; prefer AES-256 for PQ margin"
    aliases: [aes-128, aes-192, aes-256]
  - family: chacha20
    status: quantum-safe
    nist_level: 1
    recommendation: "256-bit key provides adequate PQ margin"
    aliases: [chacha, xchacha20]
  - family: camellia
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe symmetric cipher"
  - family: aria
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe symmetric cipher"
  - family: seed
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe symmetric cipher (KS) — acceptable"
  - family: sm4
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe symmetric cipher (CN) — acceptable"
  - family: salsa20
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe; consider ChaCha20 for stronger margins"
    aliases: [xsalsa20]
  - family: serpent
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe; AES is more widely audited"
  - family: twofish
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe; AES is more widely audited"

  # ── Quantum-safe hash (Grover halves effective digest) ──
  - family: sha-256
    status: quantum-safe
    nist_level: 1
    recommendation: "128-bit PQ security; adequate"
    aliases: [sha256]
  - family: sha-384
    status: quantum-safe
    nist_level: 3
    recommendation: "192-bit PQ security"
    aliases: [sha384]
  - family: sha-512
    status: quantum-safe
    nist_level: 5
    recommendation: "256-bit PQ security"
    aliases: [sha512]
  - family: sha-224
    status: quantum-safe
    nist_level: 1
    recommendation: "112-bit PQ security; consider SHA-256+"
    aliases: [sha224]
  - family: sha3-256
    status: quantum-safe
    nist_level: 1
    recommendation: "128-bit PQ security"
  - family: sha3-384
    status: quantum-safe
    nist_level: 3
    recommendation: "192-bit PQ security"
  - family: sha3-512
    status: quantum-safe
    nist_level: 5
    recommendation: "256-bit PQ security"
  - family: blake2
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe with 256-bit output"
    aliases: [blake2b, blake2s]
  - family: blake3
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe with 256-bit output"
  - family: shake-128
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe (SHA-3 family)"
    aliases: [shake128]
  - family: shake-256
    status: quantum-safe
    nist_level: 3
    recommendation: "Quantum-safe (SHA-3 family)"
    aliases: [shake256]

  # ── MAC primitives (quantum-safe when underlying is) ──
  - family: hmac
    status: quantum-safe
    nist_level: 1
    recommendation: "HMAC inherits the underlying hash's PQ strength"
  - family: hmac-sha-256
    status: quantum-safe
    nist_level: 1
    recommendation: "128-bit PQ security"
    aliases: [hmac-sha256]
  - family: hmac-sha-384
    status: quantum-safe
    nist_level: 3
    recommendation: "192-bit PQ security"
  - family: hmac-sha-512
    status: quantum-safe
    nist_level: 5
    recommendation: "256-bit PQ security"
  - family: cmac
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe MAC (when paired with AES-256)"
  - family: kmac
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe MAC (SHA-3 family)"
  - family: poly1305
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe one-time MAC (paired with ChaCha20)"
  - family: gmac
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe MAC; part of AES-GCM"

  # ── KDF / password hashing (quantum-safe; PQ margin per underlying) ──
  - family: pbkdf2
    status: quantum-safe
    nist_level: 1
    recommendation: "Use ≥600k iterations + SHA-256 minimum"
  - family: hkdf
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe KDF (RFC 5869)"
  - family: scrypt
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe memory-hard KDF"
  - family: bcrypt
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe password hash; consider Argon2id for new code"
  - family: argon2
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe password hash (PHC winner); use Argon2id variant"
    aliases: [argon2i, argon2d, argon2id]
  - family: concatkdf
    status: quantum-safe
    nist_level: 1
    recommendation: "Quantum-safe KDF (SP 800-56C)"
    aliases: [concatkdf-hmac, x963kdf]

  # ── Post-quantum NIST standards ──
  - family: ml-kem
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST PQC standard (FIPS 203) — recommended for key encapsulation"
    aliases: [kyber, kyber-512, kyber-768, kyber-1024, crystals-kyber]
  - family: ml-dsa
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST PQC standard (FIPS 204) — recommended for signatures"
    aliases: [dilithium, dilithium2, dilithium3, dilithium5, crystals-dilithium]
  - family: slh-dsa
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST PQC standard (FIPS 205) — stateless hash-based signatures"
    aliases: [sphincs, sphincs+, sphincsplus]
  - family: fn-dsa
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST PQC standard (draft FIPS 206) — Falcon successor"
    aliases: [falcon, falcon-512, falcon-1024]
  - family: xmss
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST SP 800-208 — stateful hash-based signatures"
    aliases: [xmss-mt]
  - family: lms
    status: quantum-safe
    nist_level: 5
    recommendation: "NIST SP 800-208 — stateful hash-based signatures"
    aliases: [hss]
  - family: bike
    status: quantum-safe
    nist_level: 1
    recommendation: "NIST PQC alternative (KEM, code-based)"
  - family: hqc
    status: quantum-safe
    nist_level: 1
    recommendation: "NIST PQC alternative (KEM, code-based)"
  - family: frodokem
    status: quantum-safe
    nist_level: 1
    recommendation: "Conservative LWE-based KEM (slower than ML-KEM)"
    aliases: [frodo]

  # ── Broken (classically broken regardless of quantum) ──
  - family: md5
    status: broken
    nist_level: 0
    recommendation: "Do not use — collision attacks practical since 2004"
  - family: md4
    status: broken
    nist_level: 0
    recommendation: "Do not use — collision attacks trivial"
  - family: md2
    status: broken
    nist_level: 0
    recommendation: "Do not use — collision attacks practical"
  - family: sha-1
    status: broken
    nist_level: 0
    recommendation: "Do not use — collision attacks practical since 2017"
    aliases: [sha1]
  - family: des
    status: broken
    nist_level: 0
    recommendation: "Do not use — 56-bit key is trivially brutable"
  - family: 3des
    status: broken
    nist_level: 0
    recommendation: "Deprecated by NIST (2024) — migrate to AES"
    aliases: [tripledes, triple-des]
  - family: rc2
    status: broken
    nist_level: 0
    recommendation: "Do not use — multiple known attacks"
  - family: rc4
    status: broken
    nist_level: 0
    recommendation: "Do not use — RFC 7465 (banned in TLS)"
  - family: rc5
    status: broken
    nist_level: 0
    recommendation: "Do not use — distinguishing attacks known"
  - family: rc6
    status: broken
    nist_level: 0
    recommendation: "Do not use — distinguishing attacks known"
  - family: ripemd
    status: broken
    nist_level: 0
    recommendation: "RIPEMD-160 not yet broken but deprecated; use SHA-256+"
    aliases: [ripemd-160, ripemd160]
  - family: blowfish
    status: broken
    nist_level: 0
    recommendation: "64-bit block size makes it weak for modern use; use AES"
  - family: idea
    status: broken
    nist_level: 0
    recommendation: "Patent expired but rarely used; prefer AES"
  - family: cast5
    status: broken
    nist_level: 0
    recommendation: "64-bit block size makes it weak for modern use; use AES"
  - family: cast6
    status: broken
    nist_level: 0
    recommendation: "Use AES; CAST6 is rarely audited"
  - family: skipjack
    status: broken
    nist_level: 0
    recommendation: "Deprecated NSA cipher; use AES"
  - family: whirlpool
    status: broken
    nist_level: 0
    recommendation: "Rarely audited; prefer SHA-3 / BLAKE3"
```

- [ ] **Step 4: Implement the YAML loader**

Replace contents of `cli/internal/scanner/quantum/quantum.go` (keep the package declaration and the `Info` type, but replace everything else):
```go
// Package quantum provides a shared quantum-readiness classification table
// for cryptographic algorithms. It is used by all language scanners and the
// output writers. Table data is embedded from quantum-readiness.yml.
package quantum

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

//go:embed quantum-readiness.yml
var quantumYAML []byte

// Info holds the quantum readiness classification for a crypto algorithm.
type Info struct {
	Status         types.QuantumStatus
	NistLevel      int    // 0 if not applicable
	Recommendation string // migration guidance
}

// yamlSchema mirrors the structure of quantum-readiness.yml.
type yamlSchema struct {
	Version                  int                 `yaml:"version"`
	NonAlgorithmAssetTypes   []string            `yaml:"non_algorithm_asset_types"`
	Algorithms               []yamlAlgorithmEntry `yaml:"algorithms"`
}

type yamlAlgorithmEntry struct {
	Family         string   `yaml:"family"`
	Status         string   `yaml:"status"`
	NistLevel      int      `yaml:"nist_level"`
	Recommendation string   `yaml:"recommendation"`
	Aliases        []string `yaml:"aliases"`
}

var (
	// table maps lowercase family names (and aliases) to Info.
	table map[string]Info
	// nonAlgorithmAssetTypes is the set of types.AssetType strings that should
	// skip the algorithm lookup entirely (cert, related-crypto-material, library).
	nonAlgorithmAssetTypes map[string]bool
)

// familySuffixRE strips -<digits>(-<mode>)? suffix for fuzzy family matching.
// Examples: "RSA-2048" → "rsa", "aes-128-gcm" → "aes", "ECDSA-P256" → "ecdsa".
// Preserves names where the suffix is part of the canonical name (sha-256, sha3-512).
var familySuffixRE = regexp.MustCompile(`(?i)-\d+(-[a-z]+)?$`)

func init() {
	var s yamlSchema
	if err := yaml.Unmarshal(quantumYAML, &s); err != nil {
		panic(fmt.Sprintf("quantum-readiness.yml is malformed: %v", err))
	}
	if s.Version != 1 {
		panic(fmt.Sprintf("quantum-readiness.yml unsupported version: %d", s.Version))
	}
	table = make(map[string]Info, len(s.Algorithms)*2)
	for _, a := range s.Algorithms {
		fam := strings.ToLower(a.Family)
		info := Info{
			Status:         types.QuantumStatus(a.Status),
			NistLevel:      a.NistLevel,
			Recommendation: a.Recommendation,
		}
		table[fam] = info
		for _, alias := range a.Aliases {
			table[strings.ToLower(alias)] = info
		}
	}
	nonAlgorithmAssetTypes = make(map[string]bool, len(s.NonAlgorithmAssetTypes))
	for _, t := range s.NonAlgorithmAssetTypes {
		nonAlgorithmAssetTypes[strings.ToLower(t)] = true
	}
}

// GetInfo returns the quantum readiness info for a given algorithm family.
// The family name is normalized (suffix-stripped, lowercased, then alias-resolved).
// Returns QuantumUnknown if no match.
func GetInfo(algorithmFamily string) Info {
	if algorithmFamily == "" {
		return Info{Status: types.QuantumUnknown, Recommendation: "Algorithm not recognized — review manually"}
	}
	// Exact match first (handles cases like "sha-256" where the suffix is part of name).
	if info, ok := table[strings.ToLower(algorithmFamily)]; ok {
		return info
	}
	// Try suffix-stripped form.
	if family := normalizeFamily(algorithmFamily); family != "" {
		if info, ok := table[family]; ok {
			return info
		}
	}
	return Info{Status: types.QuantumUnknown, Recommendation: "Algorithm not recognized — review manually"}
}

// GetInfoForAsset is like GetInfo but skips the lookup for non-algorithm asset
// types (certificate, related-crypto-material, library) and returns
// QuantumNotApplicable, telling output writers to omit the quantum field.
func GetInfoForAsset(algorithmFamily, assetType string) Info {
	if assetType != "" && nonAlgorithmAssetTypes[strings.ToLower(assetType)] {
		return Info{Status: types.QuantumNotApplicable}
	}
	return GetInfo(algorithmFamily)
}

// normalizeFamily strips a -<digits>(-<mode>)? suffix and lowercases.
// Preserves the input if no match (so GetInfo can fall back cleanly).
// Returns "" for empty input.
func normalizeFamily(s string) string {
	if s == "" {
		return ""
	}
	lower := strings.ToLower(strings.TrimSpace(s))
	// Check if the exact lowercase form is in the table — if so, return as-is
	// to preserve names like "sha-256" or "sha3-512" where the suffix is part
	// of the canonical name.
	if _, ok := table[lower]; ok {
		return lower
	}
	stripped := familySuffixRE.ReplaceAllString(lower, "")
	return stripped
}
```

- [ ] **Step 5: Run + verify pass**

```bash
cd cli && go test ./internal/scanner/quantum/ -v
```

Expected: PASS (all 5 tests).

- [ ] **Step 6: Run full test suite**

```bash
cd cli && go test ./... -count=1
```

Expected: PASS. (Some downstream tests may need updates if they pinned old behavior — fix those tests to use the new GetInfoForAsset where appropriate.)

---

### Task 2.3: Wire `QuantumNotApplicable` through output writers

**Files:**
- Modify: `cli/internal/output/converter.go` (`buildFindingProperties` — line 425-443)
- Modify: `cli/internal/output/text.go` (`Quantum Readiness:` line — text.go:160-182)
- Modify: `cli/internal/output/pdf.go` (`addQuantumReadinessSection` — pdf.go:441+)
- Test: existing `text_test.go`, `cyclonedx_json_test.go`

- [ ] **Step 1: Write failing tests**

In `cli/internal/output/text_test.go`, add:
```go
func TestText_QuantumNotApplicable_OmitsField(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{
				ID: "1", Name: "openssl", AssetType: types.AssetType("library"),
				Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
			},
		},
	}
	var buf bytes.Buffer
	(&TextWriter{}).WriteScanResult(&buf, result)
	out := buf.String()
	if strings.Contains(out, "not-applicable") {
		t.Errorf("text output should NOT render not-applicable literal; got:\n%s", out)
	}
	if strings.Contains(out, "Unknown") && strings.Contains(out, "openssl") {
		t.Error("text output should NOT render Unknown for not-applicable findings")
	}
}
```

In `cli/internal/output/converter_test.go`, add:
```go
func TestConverter_QuantumNotApplicable_OmitsProperty(t *testing.T) {
	f := &types.Finding{
		ID: "1", Name: "openssl", AssetType: types.AssetType("library"),
		Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
	}
	comp := convertFinding(f)
	for _, p := range comp.Properties {
		if p.Name == "quantumStatus" {
			t.Errorf("property quantumStatus should be omitted for not-applicable; got value=%q", p.Value)
		}
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/output/ -run 'TestText_QuantumNotApplicable|TestConverter_QuantumNotApplicable' -v
```

Expected: FAIL.

- [ ] **Step 3: Update `buildFindingProperties` in converter.go**

Replace the QuantumStatus check (around line 434):
```go
if f.Properties.QuantumStatus != "" && f.Properties.QuantumStatus != types.QuantumNotApplicable {
    props = append(props, Property{Name: "quantumStatus", Value: string(f.Properties.QuantumStatus)})
}
```

- [ ] **Step 4: Update text writer**

In `cli/internal/output/text.go` around line 160 (the `// Quantum readiness` block), wrap the rendering:
```go
// Quantum readiness — skip for not-applicable findings (libraries, certs).
if f.Properties.QuantumStatus != "" && f.Properties.QuantumStatus != types.QuantumNotApplicable {
    p("    %s %s",
        c(grey, "Quantum Readiness:"),
        formatQuantumStatus(f.Properties.QuantumStatus, c, color))
}
```

(Adapt to the actual surrounding code — read text.go lines 155-185 and preserve the structure.)

- [ ] **Step 5: Update PDF writer**

In `cli/internal/output/pdf.go` `addQuantumReadinessSection` (line 441+), filter out not-applicable findings before counting. Also update `addSummarySection`'s quantum-count map (line 183-195) to skip not-applicable:
```go
qCounts := map[types.QuantumStatus]int{
    types.QuantumVulnerable: 0, types.QuantumSafe: 0,
    types.QuantumUnknown: 0, types.Broken: 0,
}
for _, f := range result.Findings {
    qs := f.Properties.QuantumStatus
    if qs == types.QuantumNotApplicable {
        continue
    }
    if qs == "" {
        qs = types.QuantumUnknown
    }
    qCounts[qs]++
}
```

- [ ] **Step 6: Run + verify pass**

```bash
cd cli && go test ./internal/output/ -run 'TestText_QuantumNotApplicable|TestConverter_QuantumNotApplicable' -v
cd cli && go test ./internal/output/ -count=1
```

Expected: PASS.

---

### Task 2.4: Phase 2 regression gate + commit

- [ ] **Step 1: Full sweep**

```bash
cd cli && go test ./... -count=1 && go vet ./... && golangci-lint run
```

Expected: clean.

- [ ] **Step 2: Smoke + verify quantum counts changed**

```bash
cd cli && go build -o /tmp/cradar-c2 ./cmd/cradar
/tmp/cradar-c2 scan ../scanner/rules/python/ --format text 2>&1 | grep -A 5 "Quantum"
```

Expected: quantum counts reflect expanded table (more "Vulnerable" / "Safe" labels, fewer "Unknown" labels).

- [ ] **Step 3: Commit**

```bash
git add cli/internal/types/enums.go \
        cli/internal/types/types_test.go \
        cli/internal/scanner/quantum/quantum.go \
        cli/internal/scanner/quantum/quantum-readiness.yml \
        cli/internal/scanner/quantum/quantum_yaml_test.go \
        cli/internal/output/converter.go \
        cli/internal/output/converter_test.go \
        cli/internal/output/text.go \
        cli/internal/output/text_test.go \
        cli/internal/output/pdf.go
git commit -m "feat(quantum): expand readiness table to ~80 algorithms via embedded yaml

Move algorithm classification from inline Go map to
cli/internal/scanner/quantum/quantum-readiness.yml. Adds full PQC
suite (ML-KEM, ML-DSA, SLH-DSA, Falcon→FN-DSA, XMSS, LMS, BIKE, HQC,
FrodoKEM) with silent canonical mapping for deprecated names (Kyber→ML-KEM,
Dilithium→ML-DSA, SPHINCS+→SLH-DSA). Adds classical gaps (ElGamal, ECIES,
KMAC, all HMAC/HKDF/PBKDF2 variants, password hashers).

normalizeFamily strips -<size>(-<mode>)? suffix so RSA-2048 / aes-128-gcm
match family root. New QuantumNotApplicable status omits quantum field
for certificates / hardcoded secrets / library findings."
```

---

# Phase 3 — PDF Option D (Commit 3)

**Goal:** Split monolithic `pdf.go` into focused package, build Option-D summary aggregators, embed go-echarts SVG charts, add compliance section, add `--baseline` diff.

**End-state commit message:**
```
feat(pdf): expand inventory report to option D layout

Split cli/internal/output/pdf.go (732 lines) into cli/internal/output/pdf/
package with focused files per section. Adds:
- aggregators for assetType / primitive / language / top-N algorithms
- quantum migration backlog table (vulnerable algorithms with file:line)
- severity bar + quantum pie SVG charts (via go-echarts/v2)
- compliance section (one tile per framework, from ComplianceResults)
- --baseline flag + diff section reusing cli/internal/diff
```

### Task 3.0: Add go-echarts dependency

- [ ] **Step 1: Add the dep**

```bash
cd cli && go get github.com/go-echarts/go-echarts/v2@latest
```

- [ ] **Step 2: Verify it builds**

```bash
cd cli && go mod tidy && go build ./...
```

Expected: clean build. New entries in `cli/go.mod` and `cli/go.sum`.

---

### Task 3.1: Create `pdf/` package skeleton + move shared helpers

**Files:**
- Create: `cli/internal/output/pdf/shared.go` (colors, severityOrder helpers)
- Create: `cli/internal/output/pdf/renderer.go` (entry function)

- [ ] **Step 1: Identify what to move**

Read `cli/internal/output/pdf.go` lines 44-94 (color vars + generatePDF + addCoverSection). These are the foundation.

- [ ] **Step 2: Create shared.go**

`cli/internal/output/pdf/shared.go`:
```go
package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Color palette shared across all PDF sections.
var (
	ColorCritical  = &props.Color{Red: 180, Green: 30, Blue: 30}
	ColorHigh      = &props.Color{Red: 220, Green: 120, Blue: 20}
	ColorMedium    = &props.Color{Red: 180, Green: 160, Blue: 20}
	ColorLow       = &props.Color{Red: 40, Green: 100, Blue: 180}
	ColorInfo      = &props.Color{Red: 120, Green: 120, Blue: 120}
	ColorWhite     = &props.Color{Red: 255, Green: 255, Blue: 255}
	ColorDarkGray  = &props.Color{Red: 60, Green: 60, Blue: 60}
	ColorLightGray = &props.Color{Red: 240, Green: 240, Blue: 240}
	ColorHeaderBg  = &props.Color{Red: 35, Green: 45, Blue: 75}
	ColorPass      = &props.Color{Red: 40, Green: 140, Blue: 40}

	BgCritical = &props.Color{Red: 255, Green: 220, Blue: 220}
	BgHigh     = &props.Color{Red: 255, Green: 235, Blue: 210}
	BgMedium   = &props.Color{Red: 255, Green: 250, Blue: 210}
	BgLow      = &props.Color{Red: 220, Green: 235, Blue: 255}
	BgInfo     = &props.Color{Red: 240, Green: 240, Blue: 240}
)

// SeverityOrder returns a sort key so SeverityCritical = 0 (sorts first).
func SeverityOrder(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	default:
		return 4
	}
}

// SeverityColor returns the foreground color for a severity badge.
func SeverityColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return ColorCritical
	case types.SeverityHigh:
		return ColorHigh
	case types.SeverityMedium:
		return ColorMedium
	case types.SeverityLow:
		return ColorLow
	default:
		return ColorInfo
	}
}

// SeverityBgColor returns the background color for a severity row/badge.
func SeverityBgColor(s types.Severity) *props.Color {
	switch s {
	case types.SeverityCritical:
		return BgCritical
	case types.SeverityHigh:
		return BgHigh
	case types.SeverityMedium:
		return BgMedium
	case types.SeverityLow:
		return BgLow
	default:
		return BgInfo
	}
}
```

- [ ] **Step 3: Create renderer.go (placeholder; sections added in later tasks)**

`cli/internal/output/pdf/renderer.go`:
```go
package pdf

import (
	"fmt"
	"io"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// Options controls optional PDF features.
type Options struct {
	// Baseline, when non-nil, enables the "Changes vs Baseline" section.
	Baseline *types.ScanResult
}

// Writer generates a detailed PDF report from scan results.
type Writer struct {
	Opts Options
}

// Format returns the name of this output format.
func (w *Writer) Format() string { return "pdf" }

// WriteScanResult writes the PDF report bytes to wr.
func (w *Writer) WriteScanResult(wr io.Writer, result *types.ScanResult) error {
	doc, err := generate(result, w.Opts)
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}
	bytes := doc.GetBytes()
	if _, err := wr.Write(bytes); err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}
	return nil
}

func generate(result *types.ScanResult, opts Options) (core.Document, error) {
	cfg := config.NewBuilder().
		WithPageNumber(props.PageNumber{
			Pattern: "Page {current} of {total}",
			Place:   props.RightBottom,
			Size:    8,
			Color:   ColorInfo,
		}).
		WithLeftMargin(10).WithTopMargin(15).WithRightMargin(10).WithBottomMargin(15).
		WithCreator("CipherRadar", true).
		WithTitle("CipherRadar CBOM Scan Report", true).
		Build()

	m := maroto.New(cfg)

	// Sections added in subsequent tasks: cover, summary, charts, findings,
	// quantum migration backlog, compliance, baseline diff, footer.
	addCover(m, result)
	addSummary(m, result)
	addCharts(m, result)
	if len(result.Findings) > 0 {
		addFindings(m, result)
		addQuantum(m, result)
	}
	addCompliance(m, result)
	if opts.Baseline != nil {
		addBaselineDiff(m, result, opts.Baseline)
	}
	addFooter(m)

	return m.Generate()
}
```

- [ ] **Step 4: Build check**

```bash
cd cli && go build ./internal/output/pdf/
```

Expected: undefined: `addCover`, `addSummary`, `addCharts`, `addFindings`, `addQuantum`, `addCompliance`, `addBaselineDiff`, `addFooter`. We add them in subsequent tasks (3.2-3.9). For now, comment out the missing calls temporarily so it builds:

```go
// addCover(m, result)
// ... (uncomment as each task lands)
```

---

### Task 3.2: Move addCoverSection → cover.go

**Files:**
- Create: `cli/internal/output/pdf/cover.go`

- [ ] **Step 1: Extract `addCoverSection` from `pdf.go:96-160`**

`cli/internal/output/pdf/cover.go`:
```go
package pdf

import (
	"fmt"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func addCover(m core.Maroto, result *types.ScanResult) {
	// Copy lines 96-160 from cli/internal/output/pdf.go (addCoverSection),
	// replacing colorHeaderBg → ColorHeaderBg, colorInfo → ColorInfo, etc.
	// Replace AppVersion reference with output.AppVersion.
	_ = fmt.Sprintf("") // placeholder — actual extraction below
	m.AddRow(15)
	m.AddRow(14, text.NewCol(12, "CipherRadar CBOM Scan Report", props.Text{
		Size: 20, Style: fontstyle.Bold, Align: align.Center, Color: ColorHeaderBg,
	}))
	m.AddRow(7, text.NewCol(12, "Cryptographic Bill of Materials Analysis", props.Text{
		Size: 11, Align: align.Center, Color: ColorInfo,
	}))
	m.AddRows(line.NewRow(2, props.Line{Color: ColorLightGray, Thickness: 0.5}))
	m.AddRow(4)

	// Metadata block (target, started, duration, version).
	duration := result.EndTime.Sub(result.StartTime).Seconds()
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf("Target: %s", result.Target), props.Text{
		Size: 10, Color: ColorDarkGray,
	})))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf("Scanned: %s", result.StartTime.Format("2006-01-02 15:04:05")), props.Text{
		Size: 10, Color: ColorDarkGray,
	})))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf("Duration: %.2fs", duration), props.Text{
		Size: 10, Color: ColorDarkGray,
	})))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf("CipherRadar v%s", output.AppVersion), props.Text{
		Size: 10, Color: ColorDarkGray,
	})))
	m.AddRow(6)
}
```

(Use Read on pdf.go:96-160 to get exact existing content and adapt — the above is shape; preserve all the niceties of the existing cover.)

- [ ] **Step 2: Build check**

```bash
cd cli && go build ./internal/output/pdf/
```

Expected: still has undefined for the other sections — that's fine, uncomment `addCover(m, result)` in renderer.go now and proceed.

---

### Task 3.3: Build `summary.go` with aggregator

**Files:**
- Create: `cli/internal/output/pdf/summary.go`
- Test: `cli/internal/output/pdf/summary_test.go`

- [ ] **Step 1: Write failing test**

`cli/internal/output/pdf/summary_test.go`:
```go
package pdf

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestAggregate_CountsByDimension(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{ID: "1", Name: "AES", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityMedium,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "AES", Primitive: "block-cipher", QuantumStatus: types.QuantumSafe,
				},
				Location: types.Location{File: "a.py"}},
			{ID: "2", Name: "AES", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityMedium,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "AES", Primitive: "block-cipher", QuantumStatus: types.QuantumSafe,
				},
				Location: types.Location{File: "b.py"}},
			{ID: "3", Name: "RSA", AssetType: types.AssetAlgorithm,
				Severity: types.SeverityHigh,
				Properties: types.CryptoProperties{
					AlgorithmFamily: "RSA", Primitive: "signature", QuantumStatus: types.QuantumVulnerable,
				},
				Location: types.Location{File: "auth.go"}},
			{ID: "4", Name: "openssl", AssetType: types.AssetType("library"),
				Properties: types.CryptoProperties{QuantumStatus: types.QuantumNotApplicable},
				Location: types.Location{File: "requirements.txt"}},
		},
	}
	s := Aggregate(result)
	if s.AssetType["algorithm"] != 3 {
		t.Errorf("AssetType[algorithm] = %d, want 3", s.AssetType["algorithm"])
	}
	if s.AssetType["library"] != 1 {
		t.Errorf("AssetType[library] = %d, want 1", s.AssetType["library"])
	}
	if s.Primitive["block-cipher"] != 2 {
		t.Errorf("Primitive[block-cipher] = %d, want 2", s.Primitive["block-cipher"])
	}
	if s.Quantum[types.QuantumNotApplicable] != 0 {
		t.Error("Quantum should not count NotApplicable in the breakdown")
	}
	if len(s.TopAlgorithms) == 0 || s.TopAlgorithms[0].Key != "AES" || s.TopAlgorithms[0].Value != 2 {
		t.Errorf("TopAlgorithms[0] = %+v, want AES=2 first", s.TopAlgorithms[0])
	}
	if s.Files != 4 {
		t.Errorf("Files = %d, want 4 (unique paths)", s.Files)
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/output/pdf/ -run TestAggregate -v
```

Expected: FAIL — undefined `Aggregate`, `KV`, etc.

- [ ] **Step 3: Implement aggregator + summary section**

`cli/internal/output/pdf/summary.go`:
```go
package pdf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// KV is a string→int pair, used for sorted breakdowns like TopAlgorithms.
type KV struct {
	Key   string
	Value int
}

// SummaryStats holds the aggregated counts used by Option-D PDF sections.
type SummaryStats struct {
	Severity      map[types.Severity]int
	Quantum       map[types.QuantumStatus]int
	AssetType     map[string]int
	Primitive     map[string]int
	Language      map[string]int
	TopAlgorithms []KV
	Files         int
	Languages     int
}

// Aggregate computes a SummaryStats from a ScanResult.
func Aggregate(result *types.ScanResult) SummaryStats {
	s := SummaryStats{
		Severity:  map[types.Severity]int{},
		Quantum:   map[types.QuantumStatus]int{},
		AssetType: map[string]int{},
		Primitive: map[string]int{},
		Language:  map[string]int{},
	}
	files := map[string]struct{}{}
	algorithms := map[string]int{}
	for _, f := range result.Findings {
		s.Severity[f.Severity]++
		if f.Properties.QuantumStatus != "" && f.Properties.QuantumStatus != types.QuantumNotApplicable {
			s.Quantum[f.Properties.QuantumStatus]++
		}
		s.AssetType[string(f.AssetType)]++
		if f.Properties.Primitive != "" {
			s.Primitive[f.Properties.Primitive]++
		}
		if f.Language != "" {
			s.Language[f.Language]++
		}
		if f.Location.File != "" {
			files[f.Location.File] = struct{}{}
		}
		if f.Properties.AlgorithmFamily != "" {
			algorithms[f.Properties.AlgorithmFamily]++
		}
	}
	s.Files = len(files)
	s.Languages = len(s.Language)
	for k, v := range algorithms {
		s.TopAlgorithms = append(s.TopAlgorithms, KV{Key: k, Value: v})
	}
	sort.Slice(s.TopAlgorithms, func(i, j int) bool {
		if s.TopAlgorithms[i].Value != s.TopAlgorithms[j].Value {
			return s.TopAlgorithms[i].Value > s.TopAlgorithms[j].Value
		}
		return s.TopAlgorithms[i].Key < s.TopAlgorithms[j].Key
	})
	if len(s.TopAlgorithms) > 10 {
		s.TopAlgorithms = s.TopAlgorithms[:10]
	}
	return s
}

func addSummary(m core.Maroto, result *types.ScanResult) {
	s := Aggregate(result)

	// Header.
	m.AddRow(10, text.NewCol(12, "Scan Summary", props.Text{
		Size: 14, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf(
		"Findings: %d   Files: %d   Languages: %d   Duration: %.2fs",
		len(result.Findings), s.Files, s.Languages,
		result.EndTime.Sub(result.StartTime).Seconds(),
	), props.Text{Size: 10, Color: ColorDarkGray})))
	m.AddRow(4)

	// Severity row (existing behavior preserved).
	addSummaryRow(m, "Severity Breakdown", []labeledCount{
		{"CRITICAL", s.Severity[types.SeverityCritical], ColorCritical, BgCritical},
		{"HIGH", s.Severity[types.SeverityHigh], ColorHigh, BgHigh},
		{"MEDIUM", s.Severity[types.SeverityMedium], ColorMedium, BgMedium},
		{"LOW", s.Severity[types.SeverityLow], ColorLow, BgLow},
		{"INFO", s.Severity[types.SeverityInfo], ColorInfo, BgInfo},
	})

	// Quantum row.
	addSummaryRow(m, "Quantum Readiness", []labeledCount{
		{"Vulnerable", s.Quantum[types.QuantumVulnerable], ColorCritical, BgCritical},
		{"Safe", s.Quantum[types.QuantumSafe], ColorPass, &props.Color{Red: 220, Green: 245, Blue: 220}},
		{"Unknown", s.Quantum[types.QuantumUnknown], ColorMedium, BgMedium},
		{"Broken", s.Quantum[types.Broken], &props.Color{Red: 140, Green: 20, Blue: 20}, BgCritical},
	})

	// Asset type row (new — Option D).
	addBreakdownRow(m, "Asset Type", mapToSorted(s.AssetType))

	// Primitive row (new — Option D).
	addBreakdownRow(m, "Cryptographic Primitives", mapToSorted(s.Primitive))

	// Language row (new — Option D).
	addBreakdownRow(m, "Languages", mapToSorted(s.Language))

	// Top algorithms row (new — Option D).
	if len(s.TopAlgorithms) > 0 {
		addBreakdownRow(m, "Top Algorithms", s.TopAlgorithms)
	}
	m.AddRow(4)
}

type labeledCount struct {
	label string
	count int
	color *props.Color
	bg    *props.Color
}

func addSummaryRow(m core.Maroto, header string, items []labeledCount) {
	m.AddRow(8, text.NewCol(12, header, props.Text{
		Size: 11, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	cols := make([]core.Col, 0, len(items)+1)
	for _, it := range items {
		label := fmt.Sprintf("%s: %d", it.label, it.count)
		c := col.New(2).Add(text.New(label, props.Text{
			Size: 9, Style: fontstyle.Bold, Align: align.Center, Top: 2, Color: it.color,
		})).WithStyle(&props.Cell{
			BackgroundColor: it.bg, BorderType: border.Full, BorderColor: it.color, BorderThickness: 0.3,
		})
		cols = append(cols, c)
	}
	// Pad to 12 grid units.
	used := len(items) * 2
	if used < 12 {
		cols = append(cols, col.New(12-used))
	}
	m.AddRow(10, cols...)
	m.AddRow(4)
}

func addBreakdownRow(m core.Maroto, header string, kvs []KV) {
	m.AddRow(8, text.NewCol(12, header, props.Text{
		Size: 11, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	parts := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		parts = append(parts, fmt.Sprintf("%s: %d", kv.Key, kv.Value))
	}
	m.AddRow(6, col.New(12).Add(text.New(strings.Join(parts, "   "), props.Text{
		Size: 9, Color: ColorDarkGray,
	})))
	m.AddRow(3)
}

func mapToSorted(m map[string]int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}
```

- [ ] **Step 4: Run + verify pass**

```bash
cd cli && go test ./internal/output/pdf/ -run TestAggregate -v
```

Expected: PASS. Build the package too: `go build ./internal/output/pdf/`.

---

### Task 3.4: Build `findings.go` (preserve existing behavior)

**Files:**
- Create: `cli/internal/output/pdf/findings.go`

- [ ] **Step 1: Copy existing findings table**

Read `cli/internal/output/pdf.go:289-439` (`addFindingsTable`) and copy into `cli/internal/output/pdf/findings.go` as `addFindings`, renaming color refs to capitalized exports (ColorXxx) and helper calls to package locals (SeverityOrder, SeverityColor, SeverityBgColor — from shared.go). Replace `severityOrder`, `severityColor`, `severityBgColor` with the exported names.

- [ ] **Step 2: Build check**

```bash
cd cli && go build ./internal/output/pdf/
```

Expected: clean (after uncommenting `addFindings` in renderer.go).

---

### Task 3.5: Build `quantum.go` with migration backlog

**Files:**
- Create: `cli/internal/output/pdf/quantum.go`
- Test: `cli/internal/output/pdf/quantum_test.go`

- [ ] **Step 1: Write failing test**

`cli/internal/output/pdf/quantum_test.go`:
```go
package pdf

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestQuantumMigrationBacklog_Top5(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			mkFinding("RSA", types.QuantumVulnerable, "auth.go"),
			mkFinding("RSA", types.QuantumVulnerable, "tokens.go"),
			mkFinding("ECDSA", types.QuantumVulnerable, "jwt.go"),
			mkFinding("MD5", types.Broken, "legacy.go"),
			mkFinding("AES", types.QuantumSafe, "crypto.go"), // not in backlog
		},
	}
	backlog := buildMigrationBacklog(result, 5)
	if len(backlog) != 3 {
		t.Errorf("backlog len = %d, want 3 (RSA, ECDSA, MD5)", len(backlog))
	}
	if backlog[0].Algorithm != "RSA" || backlog[0].Count != 2 {
		t.Errorf("backlog[0] = %+v, want RSA count=2", backlog[0])
	}
}

func mkFinding(algo string, qs types.QuantumStatus, file string) types.Finding {
	return types.Finding{
		Name: algo, AssetType: types.AssetAlgorithm,
		Properties: types.CryptoProperties{
			AlgorithmFamily: algo, QuantumStatus: qs,
		},
		Location: types.Location{File: file, StartLine: 1},
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/output/pdf/ -run TestQuantumMigrationBacklog -v
```

Expected: FAIL.

- [ ] **Step 3: Implement**

`cli/internal/output/pdf/quantum.go`:
```go
package pdf

import (
	"fmt"
	"sort"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// BacklogEntry summarizes a vulnerable algorithm awaiting migration.
type BacklogEntry struct {
	Algorithm      string
	Count          int
	Status         types.QuantumStatus
	Recommendation string
	Examples       []string // up to 3 file:line locations
}

// buildMigrationBacklog returns the top N vulnerable / broken algorithm
// families in the scan, sorted by count desc.
func buildMigrationBacklog(result *types.ScanResult, top int) []BacklogEntry {
	groups := map[string]*BacklogEntry{}
	for _, f := range result.Findings {
		qs := f.Properties.QuantumStatus
		if qs != types.QuantumVulnerable && qs != types.Broken {
			continue
		}
		key := f.Properties.AlgorithmFamily
		if key == "" {
			key = f.Name
		}
		e, ok := groups[key]
		if !ok {
			info := quantum.GetInfo(key)
			e = &BacklogEntry{
				Algorithm: key, Status: qs, Recommendation: info.Recommendation,
			}
			groups[key] = e
		}
		e.Count++
		if len(e.Examples) < 3 {
			e.Examples = append(e.Examples, fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine))
		}
	}
	out := make([]BacklogEntry, 0, len(groups))
	for _, e := range groups {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Algorithm < out[j].Algorithm
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

func addQuantum(m core.Maroto, result *types.ScanResult) {
	backlog := buildMigrationBacklog(result, 10)
	if len(backlog) == 0 {
		return
	}

	m.AddRow(10, text.NewCol(12, "Quantum Migration Backlog", props.Text{
		Size: 14, Style: fontstyle.Bold, Color: ColorCritical,
	}))
	m.AddRow(4)

	// Table header.
	header := props.Text{Size: 8, Style: fontstyle.Bold, Align: align.Center, Top: 2, Color: ColorWhite}
	cellH := &props.Cell{BackgroundColor: ColorHeaderBg}
	m.AddRow(8,
		col.New(2).Add(text.New("Algorithm", header)).WithStyle(cellH),
		col.New(1).Add(text.New("Count", header)).WithStyle(cellH),
		col.New(2).Add(text.New("Status", header)).WithStyle(cellH),
		col.New(4).Add(text.New("Recommendation", header)).WithStyle(cellH),
		col.New(3).Add(text.New("Examples (top 3)", header)).WithStyle(cellH),
	)

	cell := props.Text{Size: 7, Top: 1.5, Color: &props.BlackColor, Align: align.Left, Left: 1}
	border := &props.Cell{BackgroundColor: BgCritical, BorderType: border.Full, BorderColor: ColorLightGray, BorderThickness: 0.1}
	for _, e := range backlog {
		examples := ""
		for i, ex := range e.Examples {
			if i > 0 {
				examples += "; "
			}
			examples += ex
		}
		m.AddRow(7,
			col.New(2).Add(text.New(e.Algorithm, cell)).WithStyle(border),
			col.New(1).Add(text.New(fmt.Sprintf("%d", e.Count), props.Text{Size: 7, Top: 1.5, Align: align.Center, Color: &props.BlackColor})).WithStyle(border),
			col.New(2).Add(text.New(string(e.Status), cell)).WithStyle(border),
			col.New(4).Add(text.New(e.Recommendation, cell)).WithStyle(border),
			col.New(3).Add(text.New(examples, cell)).WithStyle(border),
		)
	}
	m.AddRow(6)
}
```

- [ ] **Step 4: Run + verify pass**

```bash
cd cli && go test ./internal/output/pdf/ -run TestQuantumMigrationBacklog -v
```

Expected: PASS.

---

### Task 3.6: Build `charts.go` (severity bar + quantum pie)

**Files:**
- Create: `cli/internal/output/pdf/charts.go`

- [ ] **Step 1: Implement chart helper**

`cli/internal/output/pdf/charts.go`:
```go
package pdf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"

	"github.com/johnfercher/maroto/v2/pkg/components/code"
	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/image"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func addCharts(m core.Maroto, result *types.ScanResult) {
	stats := Aggregate(result)
	if len(result.Findings) == 0 {
		return
	}

	m.AddRow(10, text.NewCol(12, "Visual Summary", props.Text{
		Size: 12, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))

	severityPNG, err1 := severityBarPNG(stats)
	quantumPNG, err2 := quantumPiePNG(stats)
	if err1 != nil || err2 != nil {
		// Charts are non-fatal — log to stderr and skip.
		fmt.Fprintf(os.Stderr, "WARNING: chart generation failed (severity=%v, quantum=%v); PDF will skip charts\n", err1, err2)
		return
	}

	tmpDir, _ := os.MkdirTemp("", "cradar-charts-*")
	defer os.RemoveAll(tmpDir)
	sevPath := filepath.Join(tmpDir, "severity.png")
	quaPath := filepath.Join(tmpDir, "quantum.png")
	_ = os.WriteFile(sevPath, severityPNG, 0644)
	_ = os.WriteFile(quaPath, quantumPNG, 0644)

	m.AddRow(50,
		col.New(6).Add(image.NewFromFile(sevPath, props.Rect{Center: true})),
		col.New(6).Add(image.NewFromFile(quaPath, props.Rect{Center: true})),
	)
	_ = code.New // import-stub guard if not used elsewhere
}

func severityBarPNG(s SummaryStats) ([]byte, error) {
	bar := charts.NewBar()
	bar.SetGlobalOptions(charts.WithTitleOpts(opts.Title{Title: "Severity"}))
	bar.SetXAxis([]string{"CRIT", "HIGH", "MED", "LOW", "INFO"}).
		AddSeries("count", []opts.BarData{
			{Value: s.Severity[types.SeverityCritical]},
			{Value: s.Severity[types.SeverityHigh]},
			{Value: s.Severity[types.SeverityMedium]},
			{Value: s.Severity[types.SeverityLow]},
			{Value: s.Severity[types.SeverityInfo]},
		})
	var buf bytes.Buffer
	if err := bar.Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func quantumPiePNG(s SummaryStats) ([]byte, error) {
	pie := charts.NewPie()
	pie.SetGlobalOptions(charts.WithTitleOpts(opts.Title{Title: "Quantum Mix"}))
	pie.AddSeries("quantum", []opts.PieData{
		{Name: "Vulnerable", Value: s.Quantum[types.QuantumVulnerable]},
		{Name: "Safe", Value: s.Quantum[types.QuantumSafe]},
		{Name: "Unknown", Value: s.Quantum[types.QuantumUnknown]},
		{Name: "Broken", Value: s.Quantum[types.Broken]},
	})
	var buf bytes.Buffer
	if err := pie.Render(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

**Note for implementer:** go-echarts `Render` returns HTML wrapping a JS chart. For PDF embedding we need PNG/SVG bytes. If go-echarts doesn't expose a server-side renderer, fall back to drawing simple bars/pie using maroto v2 primitives directly (no external dep). The chart helper should degrade gracefully — return `nil, nil` on unsupported and skip the row. Verify this during implementation; if go-echarts doesn't fit, the fallback is a maroto-native rendering.

- [ ] **Step 2: Build check + acceptance**

```bash
cd cli && go build ./internal/output/pdf/
```

If go-echarts can't produce PNG server-side without a browser, **replace this task's chart with a simple maroto-native bar diagram** using colored cells of varying widths — accept the reduced fidelity rather than dragging in a headless browser dependency. Document the decision inline in `charts.go`.

---

### Task 3.7: Build `compliance.go`

**Files:**
- Create: `cli/internal/output/pdf/compliance.go`

- [ ] **Step 1: Implement**

```bash
grep -n "ComplianceResults" cli/internal/types/scan.go
```

If `types.ScanResult` has a `ComplianceResults` field, use it; if it doesn't, this section is a no-op stub that future framework integration can fill in. Check first.

`cli/internal/output/pdf/compliance.go`:
```go
package pdf

import (
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// addCompliance renders one tile per framework that was evaluated. No-op if
// no compliance results are present on the ScanResult.
func addCompliance(m core.Maroto, result *types.ScanResult) {
	// TODO: implement once types.ScanResult has a stable ComplianceResults
	// field. For commit 3 we ship a no-op stub so the spec's compliance
	// section is wired without requiring framework integration changes.
	// Re-visit when ADR-023 framework results land in types.ScanResult.
	_ = result
}
```

(This is one of the few places where a stub is acceptable — it preserves the renderer.go call site without inventing data shapes that don't yet exist in the types package.)

---

### Task 3.8: Build `diff.go` + wire `--baseline` flag

**Files:**
- Create: `cli/internal/output/pdf/diff.go`
- Modify: `cli/internal/cmd/scan.go`
- Modify: `cli/internal/output/writer.go` (PDF writer needs Options)

- [ ] **Step 1: Implement diff.go**

```bash
grep -n "func Diff\|type DiffResult" cli/internal/diff/diff.go
```

Read the existing `cli/internal/diff/diff.go` API. Implement `addBaselineDiff` using whatever public API exists:

`cli/internal/output/pdf/diff.go`:
```go
package pdf

import (
	"fmt"

	"github.com/johnfercher/maroto/v2/pkg/components/col"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"

	"github.com/nk-sentinel/cipherradar/cli/internal/diff"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func addBaselineDiff(m core.Maroto, current, baseline *types.ScanResult) {
	d := diff.Compute(baseline, current) // adapt to actual diff API
	if d == nil {
		return
	}
	m.AddRow(10, text.NewCol(12, "Changes vs Baseline", props.Text{
		Size: 14, Style: fontstyle.Bold, Color: ColorHeaderBg,
	}))
	m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf(
		"Added: %d   Resolved: %d   Unchanged: %d",
		len(d.Added), len(d.Resolved), len(d.Unchanged),
	), props.Text{Size: 10, Align: align.Center, Color: ColorDarkGray})))

	if len(d.Added) > 0 {
		m.AddRow(8, text.NewCol(12, "Top 10 New Findings", props.Text{
			Size: 11, Style: fontstyle.Bold, Color: ColorCritical,
		}))
		for i, f := range d.Added {
			if i >= 10 {
				break
			}
			m.AddRow(5, col.New(12).Add(text.New(fmt.Sprintf(
				"  [%s] %s — %s:%d",
				f.Severity, f.Name, f.Location.File, f.Location.StartLine,
			), props.Text{Size: 8, Color: SeverityColor(f.Severity)})))
		}
	}
	m.AddRow(4)
}
```

(Adapt the actual `diff.Compute` call and `d.Added/Resolved/Unchanged` shape to whatever the existing `cli/internal/diff/diff.go` exposes.)

- [ ] **Step 2: Add `--baseline` flag in scan.go**

In `cli/internal/cmd/scan.go` near the other flags (around line 48):
```go
scanCmd.Flags().String("baseline", "",
    "compare against a previous scan's CycloneDX JSON; adds 'Changes vs Baseline' section to PDF reports")
```

- [ ] **Step 3: Wire baseline parsing and propagate to writer**

In `writeOutputs` (around `scan.go:380`), after format resolution, load the baseline file once if `--baseline` is set:
```go
baselineFlag, _ := cmd.Flags().GetString("baseline")
var baselineResult *types.ScanResult
if baselineFlag != "" {
    baselineBOM, err := output.LoadBOMAsScanResult(baselineFlag)
    if err != nil {
        return nil, fmt.Errorf("baseline: %w", err)
    }
    baselineResult = baselineBOM
}
// When dispatching to PDF writer, pass Options{Baseline: baselineResult}.
```

Add a helper `output.LoadBOMAsScanResult` in `cli/internal/output/converter.go` (or a new file `cli/internal/output/loader.go`) that reads a CycloneDX JSON file and returns a `*types.ScanResult` containing only the Findings derived from its Components — enough for the diff to compare.

- [ ] **Step 4: Update writer factory**

In `cli/internal/output/writer.go`, change the `pdf` case to return an instance that can accept Options. Either:
- Make `WriterFactory` accept an `Options` parameter (breaking change)
- Or have `WriterFactory("pdf")` return a `*pdf.Writer{}` and let the caller set `.Opts` post-construction

The second is less invasive:
```go
case "pdf":
    return &pdf.Writer{}, nil
```
And the caller in `scan.go` does:
```go
if pw, ok := w.(*pdf.Writer); ok && baselineResult != nil {
    pw.Opts.Baseline = baselineResult
}
```

---

### Task 3.9: Replace `cli/internal/output/pdf.go` with package import

**Files:**
- Modify: `cli/internal/output/writer.go`
- Delete: `cli/internal/output/pdf.go` and `cli/internal/output/pdf_test.go`

- [ ] **Step 1: Confirm pdf/ package compiles standalone**

```bash
cd cli && go build ./internal/output/pdf/
```

- [ ] **Step 2: Update writer.go to use new package**

In `cli/internal/output/writer.go`, replace the `&PDFWriter{}` (or equivalent) construction with `&pdf.Writer{}` and import `pdf "github.com/nk-sentinel/cipherradar/cli/internal/output/pdf"`.

- [ ] **Step 3: Delete old pdf.go + pdf_test.go**

```bash
rm cli/internal/output/pdf.go cli/internal/output/pdf_test.go
```

- [ ] **Step 4: Full build + test**

```bash
cd cli && go build ./... && go test ./... -count=1
```

Expected: clean.

---

### Task 3.10: Phase 3 regression gate + commit

- [ ] **Step 1: Lint + vet + test**

```bash
cd cli && go vet ./... && golangci-lint run && go test ./... -count=1
```

- [ ] **Step 2: Manual PDF smoke**

```bash
cd cli && go build -o /tmp/cradar-c3 ./cmd/cradar
/tmp/cradar-c3 scan ../scanner/rules/python/ --format pdf --output /tmp/c3-report.pdf 2>&1 | tail -5
view.sh /tmp/c3-report.pdf
```

Visually inspect via FileBrowser: cover, summary with all breakdowns, charts (or fallback), findings table, quantum backlog table, footer.

- [ ] **Step 3: Test --baseline**

```bash
/tmp/cradar-c3 scan ../scanner/rules/python/ --format cyclonedx-json --output /tmp/c3-baseline.json
/tmp/cradar-c3 scan ../scanner/rules/python/ --format pdf --baseline /tmp/c3-baseline.json --output /tmp/c3-diff.pdf
view.sh /tmp/c3-diff.pdf
```

Expected: "Changes vs Baseline" section appears (zero changes since same scan).

- [ ] **Step 4: Commit**

```bash
git add cli/internal/output/pdf/ \
        cli/internal/output/writer.go \
        cli/internal/cmd/scan.go \
        cli/go.mod cli/go.sum
git rm cli/internal/output/pdf.go cli/internal/output/pdf_test.go
git commit -m "feat(pdf): expand inventory report to option D layout

Split cli/internal/output/pdf.go (732 lines) into cli/internal/output/pdf/
package with focused files per section. Adds:
- aggregators for assetType / primitive / language / top-N algorithms
- quantum migration backlog table (vulnerable algorithms with file:line)
- severity bar + quantum pie charts (go-echarts/v2 or maroto-native fallback)
- compliance section stub (filled by future framework integration)
- --baseline flag + diff section reusing cli/internal/diff"
```

---

# Phase 4 — Scan-time Progress Visibility (Commit 4)

**Goal:** Wire scanner progress events to stderr, add always-on final summary with output paths, add `--quiet` flag.

**End-state commit message:**
```
feat(scan): always-on stderr summary + walker/pass progress events

Address user-reported silence during scan execution. Adds:
- Walker heartbeat: one line per 100 files OR every 2s, suppressed if <50 files total
- Pass 1 / Pass 2 boundary events (tree-sitter start/end, opengrep start/end)
- Always-on final summary: severity counts + duration + output path listing
- --quiet flag suppresses all the above
- --verbose now actually prints per-file scanner activity (was wired to clilog
  but scanner code didn't call it)

Duplication-avoidance rule keeps the common TTY case quiet (when stdout
already gets text-format output, stderr summary is suppressed).
```

### Task 4.1: Build progress helper + rate limiter

**Files:**
- Create: `cli/internal/cmd/progress.go`
- Test: `cli/internal/cmd/progress_test.go`

- [ ] **Step 1: Write failing test**

`cli/internal/cmd/progress_test.go`:
```go
package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgressEmitter_RateLimit(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{HeartbeatEvery: 100, MinFiles: 0, MinInterval: 100 * time.Millisecond})
	for i := 0; i < 350; i++ {
		p.WalkedFile("python", "f.py")
	}
	out := buf.String()
	// Expect heartbeats at 100, 200, 300 — three lines.
	if got := strings.Count(out, "[scan] walked"); got != 3 {
		t.Errorf("got %d heartbeats, want 3:\n%s", got, out)
	}
}

func TestProgressEmitter_QuietSuppresses(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{Quiet: true})
	for i := 0; i < 500; i++ {
		p.WalkedFile("go", "f.go")
	}
	p.PassStart(1, "tree-sitter", 412)
	if buf.Len() != 0 {
		t.Errorf("quiet mode should produce no output, got: %q", buf.String())
	}
}

func TestProgressEmitter_SuppressBelowMinFiles(t *testing.T) {
	var buf bytes.Buffer
	p := newProgressEmitter(&buf, ProgressOpts{HeartbeatEvery: 10, MinFiles: 50})
	for i := 0; i < 30; i++ {
		p.WalkedFile("go", "f.go")
	}
	if strings.Contains(buf.String(), "walked") {
		t.Errorf("should suppress heartbeat when total < MinFiles; got: %q", buf.String())
	}
}
```

- [ ] **Step 2: Run + verify failure**

```bash
cd cli && go test ./internal/cmd/ -run 'TestProgressEmitter' -v
```

Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

`cli/internal/cmd/progress.go`:
```go
package cmd

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// ProgressOpts configures progress emission cadence.
type ProgressOpts struct {
	Quiet          bool
	Verbose        bool
	HeartbeatEvery int           // emit one heartbeat per N files
	MinInterval    time.Duration // also emit if N files haven't elapsed but this duration has
	MinFiles       int           // suppress heartbeats entirely if total < MinFiles
}

// DefaultProgressOpts returns reasonable defaults.
func DefaultProgressOpts() ProgressOpts {
	return ProgressOpts{HeartbeatEvery: 100, MinInterval: 2 * time.Second, MinFiles: 50}
}

type progressEmitter struct {
	w     io.Writer
	opts  ProgressOpts
	mu    sync.Mutex
	count int
	last  time.Time
	langs map[string]int
}

func newProgressEmitter(w io.Writer, opts ProgressOpts) *progressEmitter {
	return &progressEmitter{w: w, opts: opts, last: time.Now(), langs: map[string]int{}}
}

// WalkedFile is called by the walker after each file is processed.
func (p *progressEmitter) WalkedFile(lang, path string) {
	if p.opts.Quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	if lang != "" {
		p.langs[lang]++
	}
	if p.opts.Verbose {
		fmt.Fprintf(p.w, "[scan] walk %s: %s\n", lang, path)
	}
	if p.opts.HeartbeatEvery <= 0 {
		return
	}
	due := p.count%p.opts.HeartbeatEvery == 0
	timeDue := p.opts.MinInterval > 0 && time.Since(p.last) >= p.opts.MinInterval
	if !due && !timeDue {
		return
	}
	if p.opts.MinFiles > 0 && p.count < p.opts.MinFiles {
		return
	}
	p.emitHeartbeat()
	p.last = time.Now()
}

func (p *progressEmitter) emitHeartbeat() {
	parts := make([]string, 0, len(p.langs))
	type kv struct {
		k string
		v int
	}
	ks := make([]kv, 0, len(p.langs))
	for k, v := range p.langs {
		ks = append(ks, kv{k, v})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].v > ks[j].v })
	for _, e := range ks {
		parts = append(parts, fmt.Sprintf("%s: %d", e.k, e.v))
	}
	suffix := ""
	if len(parts) > 0 {
		suffix = " (" + joinLimit(parts, 4) + ")"
	}
	fmt.Fprintf(p.w, "[scan] walked %d files%s\n", p.count, suffix)
}

// PassStart announces the start of a scan pass.
func (p *progressEmitter) PassStart(pass int, name string, fileCount int) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s starting (%d files)\n", pass, name, fileCount)
}

// PassComplete announces the end of a scan pass.
func (p *progressEmitter) PassComplete(pass int, name string, elapsed time.Duration, findings int) {
	if p.opts.Quiet {
		return
	}
	fmt.Fprintf(p.w, "[scan] pass %d: %s complete (%s, %d findings)\n", pass, name, elapsed.Round(time.Millisecond), findings)
}

func joinLimit(parts []string, limit int) string {
	if len(parts) <= limit {
		return joinComma(parts)
	}
	return joinComma(parts[:limit]) + ", ..."
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
```

- [ ] **Step 4: Run + verify pass**

```bash
cd cli && go test ./internal/cmd/ -run 'TestProgressEmitter' -v
```

Expected: PASS.

---

### Task 4.2: Build always-on final summary helper

**Files:**
- Create: `cli/internal/cmd/summary.go`
- Test: `cli/internal/cmd/summary_test.go`

- [ ] **Step 1: Write failing test**

`cli/internal/cmd/summary_test.go`:
```go
package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestEmitFinalSummary_DuplicationAvoidanceRules(t *testing.T) {
	result := &types.ScanResult{
		Findings: []types.Finding{
			{Severity: types.SeverityCritical}, {Severity: types.SeverityHigh},
			{Severity: types.SeverityMedium}, {Severity: types.SeverityLow},
		},
		StartTime: time.Now().Add(-2 * time.Second),
		EndTime:   time.Now(),
	}
	for _, tc := range []struct {
		name        string
		paths       []ResolvedOutput
		stdoutFmt   string
		wantEmit    bool
		wantPaths   int
	}{
		{"TTY+default text → suppress", nil, "text", false, 0},
		{"pipe+default JSON → emit, no paths", nil, "cyclonedx-json", true, 0},
		{"-o single file → emit with one path", []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json", Size: 1024}}, "", true, 1},
		{"-o multi → emit with both paths", []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json", Size: 1024}, {Path: "/tmp/y.pdf", Format: "pdf", Size: 32768}}, "", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			emitFinalSummary(&buf, result, tc.paths, tc.stdoutFmt, false)
			out := buf.String()
			if tc.wantEmit && !strings.Contains(out, "[scan] complete") {
				t.Errorf("expected emission, got: %q", out)
			}
			if !tc.wantEmit && out != "" {
				t.Errorf("expected suppression, got: %q", out)
			}
			pathLines := strings.Count(out, "[scan] wrote")
			if pathLines != tc.wantPaths {
				t.Errorf("path lines = %d, want %d:\n%s", pathLines, tc.wantPaths, out)
			}
		})
	}
}

func TestEmitFinalSummary_QuietSuppresses(t *testing.T) {
	var buf bytes.Buffer
	result := &types.ScanResult{Findings: []types.Finding{{Severity: types.SeverityCritical}}}
	emitFinalSummary(&buf, result, []ResolvedOutput{{Path: "/tmp/x.json", Format: "cyclonedx-json"}}, "", true)
	if buf.Len() != 0 {
		t.Errorf("--quiet must suppress everything; got: %q", buf.String())
	}
}
```

- [ ] **Step 2: Implement**

`cli/internal/cmd/summary.go`:
```go
package cmd

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ResolvedOutput is one resolved sink — a destination path with its format and final size.
type ResolvedOutput struct {
	Path   string
	Format string
	Size   int64 // bytes, post-write
}

// emitFinalSummary writes the always-on scan summary to wr. Suppressed when
// quiet is true OR when stdout is already receiving text-format output (the
// common TTY default — the text writer already includes a summary).
func emitFinalSummary(wr io.Writer, result *types.ScanResult, paths []ResolvedOutput, stdoutFormat string, quiet bool) {
	if quiet {
		return
	}
	// If text is going to stdout, the text writer already prints a summary.
	// Suppress the stderr dupe — exception: if --output is also set (paths non-empty),
	// the user is intentionally writing to file AND stdout could be silent; emit anyway.
	if stdoutFormat == "text" && len(paths) == 0 {
		return
	}
	sevCounts := map[types.Severity]int{}
	for _, f := range result.Findings {
		sevCounts[f.Severity]++
	}
	duration := result.EndTime.Sub(result.StartTime)
	fmt.Fprintf(wr, "[scan] complete in %s — %d findings (%d CRIT / %d HIGH / %d MED / %d LOW / %d INFO)\n",
		duration.Round(10_000_000), // 10ms precision
		len(result.Findings),
		sevCounts[types.SeverityCritical], sevCounts[types.SeverityHigh],
		sevCounts[types.SeverityMedium], sevCounts[types.SeverityLow],
		sevCounts[types.SeverityInfo])
	for _, p := range paths {
		abs, err := filepath.Abs(p.Path)
		if err != nil {
			abs = p.Path
		}
		fmt.Fprintf(wr, "[scan] wrote %s (%s, %s)\n", abs, p.Format, humanSize(p.Size))
	}
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
```

- [ ] **Step 3: Run + verify pass**

```bash
cd cli && go test ./internal/cmd/ -run 'TestEmitFinalSummary' -v
```

Expected: PASS.

---

### Task 4.3: Wire walker progress callback

**Files:**
- Modify: `cli/internal/scanner/walker.go`
- Modify: `cli/internal/scanner/scanner.go` (add ProgressCallback to ScanOptions)
- Modify: `cli/internal/cmd/scan.go` (construct + pass progressEmitter)

- [ ] **Step 1: Add ProgressCallback to ScanOptions**

In `cli/internal/scanner/walker.go` around line 55:
```go
type ScanOptions struct {
	Fast        bool
	StagedOnly  bool
	FileList    []string

	// Progress is called by the walker after each file. nil = no progress.
	Progress func(lang, path string)
}
```

- [ ] **Step 2: Call Progress inside the walker loop**

Find the per-file dispatch inside `ScanDirWithOptions` (somewhere in walker.go after a file is added to a scan job). After each successful job completion, invoke `opts.Progress` if non-nil. The exact site depends on the existing concurrency model — look for where `scanJobResult` is collected.

```go
// after collecting result from worker:
if opts.Progress != nil {
    opts.Progress(detectedLang, job.relPath)
}
```

- [ ] **Step 3: Wire from scan.go**

In `cli/internal/cmd/scan.go`, where `ScanDirWithOptions` is called, construct the progress emitter and pass:
```go
verbose, _ := cmd.Flags().GetBool("verbose")
quiet, _ := cmd.Flags().GetBool("quiet")
emitter := newProgressEmitter(cmd.ErrOrStderr(), ProgressOpts{
    Quiet: quiet, Verbose: verbose,
    HeartbeatEvery: 100, MinInterval: 2 * time.Second, MinFiles: 50,
})

scanOpts := scanner.ScanOptions{
    Fast: fast, StagedOnly: stagedOnly, FileList: fileList,
    Progress: emitter.WalkedFile,
}
result, err := scanner.ScanDirWithOptions(target, registry, passes, scanOpts)
```

- [ ] **Step 4: Add pass-boundary calls in scan.go**

Around the existing pass-dispatch logic (find where passes 1 and 2 are invoked):
```go
emitter.PassStart(1, "tree-sitter", fileCount)
t1 := time.Now()
// ... pass 1 logic ...
emitter.PassComplete(1, "tree-sitter", time.Since(t1), len(pass1Findings))

emitter.PassStart(2, "opengrep", fileCount)
t2 := time.Now()
// ... pass 2 logic ...
emitter.PassComplete(2, "opengrep", time.Since(t2), len(pass2Findings))
```

- [ ] **Step 5: Smoke test**

```bash
cd cli && go build -o /tmp/cradar-c4 ./cmd/cradar
/tmp/cradar-c4 scan ../scanner/rules/python/ --format cyclonedx-json --output /tmp/c4.json 2>&1 | tail -10
```

Expected (stderr):
```
[scan] pass 1: tree-sitter starting (N files)
[scan] walked 100 files (python: X, ...)
[scan] walked 200 files (...)
[scan] pass 1: tree-sitter complete (...)
[scan] pass 2: opengrep starting (...)
[scan] pass 2: opengrep complete (...)
[scan] complete in ...
[scan] wrote /tmp/c4.json (cyclonedx-json, ...)
```

---

### Task 4.4: Add `--quiet` flag + wire final summary

**Files:**
- Modify: `cli/internal/cmd/root.go` (add --quiet)
- Modify: `cli/internal/cmd/scan.go` (wire to emitFinalSummary)

- [ ] **Step 1: Add --quiet flag**

In `cli/internal/cmd/root.go` near the verbose flag (around line 21):
```go
rootCmd.PersistentFlags().Bool("quiet", false, "suppress progress and summary output to stderr")
```

- [ ] **Step 2: Resolve outputs to ResolvedOutput slice**

In `writeOutputs` in `scan.go`, after each successful write, capture path + format + size:
```go
resolved := make([]ResolvedOutput, 0, len(paths))
for _, p := range paths {
    fmtName := output.ResolveOutputFormat(p, perPathExplicit, cfgFormat, fileFallback)
    // ... existing write logic ...
    stat, _ := os.Stat(p)
    var size int64
    if stat != nil {
        size = stat.Size()
    }
    resolved = append(resolved, ResolvedOutput{Path: p, Format: fmtName, Size: size})
}
return resolved, formats, nil
```

(Refactor return signature of `writeOutputs` to return `[]ResolvedOutput` alongside formats.)

- [ ] **Step 3: Call emitFinalSummary after writeOutputs**

At the end of the scan execution function:
```go
quiet, _ := cmd.Flags().GetBool("quiet")
stdoutFmt := ""
if len(resolved) == 0 {
    // No -o → stdout got something. Re-resolve to know what format.
    stdoutFmt = output.ResolveOutputFormat("", explicitFormat, cfgFormat, output.DefaultStdoutFormat())
}
emitFinalSummary(cmd.ErrOrStderr(), result, resolved, stdoutFmt, quiet)
```

---

### Task 4.5: Phase 4 regression gate + commit

- [ ] **Step 1: Full sweep**

```bash
cd cli && go test ./... -count=1 && go vet ./... && golangci-lint run
```

- [ ] **Step 2: Manual smokes — each duplication-rule scenario**

```bash
cd cli && go build -o /tmp/cradar-c4 ./cmd/cradar

# Scenario 1: TTY+default text — expect no stderr summary (already on stdout)
/tmp/cradar-c4 scan ../scanner/rules/python/

# Scenario 2: pipe+default JSON — expect stderr summary, no path
/tmp/cradar-c4 scan ../scanner/rules/python/ | head -5

# Scenario 3: -o single — expect stderr summary + 1 path line
/tmp/cradar-c4 scan ../scanner/rules/python/ -o /tmp/c4-single.json

# Scenario 4: -o multi — expect stderr summary + N path lines
/tmp/cradar-c4 scan ../scanner/rules/python/ -o /tmp/c4-a.json -o /tmp/c4-b.pdf

# Scenario 5: --quiet — expect nothing
/tmp/cradar-c4 scan ../scanner/rules/python/ -o /tmp/c4-q.json --quiet 2>&1
```

- [ ] **Step 3: Commit**

```bash
git add cli/internal/cmd/progress.go \
        cli/internal/cmd/progress_test.go \
        cli/internal/cmd/summary.go \
        cli/internal/cmd/summary_test.go \
        cli/internal/cmd/scan.go \
        cli/internal/cmd/root.go \
        cli/internal/scanner/walker.go \
        cli/internal/scanner/scanner.go
git commit -m "feat(scan): always-on stderr summary + walker/pass progress events

Address user-reported silence during scan execution. Adds:
- Walker heartbeat: one line per 100 files OR every 2s, suppressed if <50 files total
- Pass 1 / Pass 2 boundary events (tree-sitter start/end, opengrep start/end)
- Always-on final summary: severity counts + duration + output path listing
- --quiet flag suppresses all the above
- --verbose now actually prints per-file scanner activity

Duplication-avoidance rule keeps the common TTY case quiet (when stdout
already gets text-format output, stderr summary is suppressed)."
```

---

# Pre-PR Final Regression

- [ ] **Full test sweep**

```bash
cd cli && go test ./... -count=1 -race
```

- [ ] **Build cross-platform sanity**

```bash
cd cli && GOOS=darwin GOARCH=arm64 go build ./cmd/cradar && GOOS=linux GOARCH=amd64 go build ./cmd/cradar
```

- [ ] **Benchmark corpus**

For each of the 7 benchmark corpus languages (per `/benchmark` skill / `cli/internal/scanner/benchmark_test.go`):

```bash
cd cli && ./cradar scan <corpus-dir> --format cyclonedx-json --output /tmp/bench-<lang>.json --validate
```

Expected: all 7 produce schema-valid output.

- [ ] **Diff CBOM vs pre-PR baseline**

```bash
diff -u <(jq -S 'del(.serialNumber, .metadata.timestamp)' /tmp/cbom-baseline/python.json) \
        <(jq -S 'del(.serialNumber, .metadata.timestamp)' /tmp/bench-python.json) | head -80
```

Expected differences only in:
- `library` assetType → `type: library` components
- `HARDCODED-SECRET` primitive → related-crypto-material with material `other`
- Quantum status field omitted on non-algorithm assetTypes (library, certificate)
- Algorithm families that newly resolve (deprecated PQC name aliases → canonical)

- [ ] **`cradar diff` works**

```bash
cd cli && ./cradar diff /tmp/bench-python.json /tmp/bench-python.json | head -5
```

Expected: no errors, "no differences" or zero adds/removes.

- [ ] **PDF visual review**

```bash
cd cli && ./cradar scan ../scanner/rules/python/ --format pdf --output /tmp/final.pdf
view.sh /tmp/final.pdf
```

Confirm: all Option-D sections render, no broken layouts, no missing data.

- [ ] **Open PR**

```bash
git push -u origin feature/cbom-export-quality
gh pr create --title "feat: cbom export quality — 4 commits" --body "$(cat <<'EOF'
## Summary

Four sequential commits improving CBOM output correctness and report depth:

1. **Validation fix** — close 2 cyclonedx 1.7 enum bleed-through bugs (HARDCODED-SECRET, library), add --strict-validate flag.
2. **Quantum expansion** — ~30 → ~80 algorithm table via embedded YAML, PQC alias mapping, QuantumNotApplicable for non-algorithm assets.
3. **PDF Option D** — split monolith into focused package, add assetType/primitive/top-N/quantum-backlog/charts/compliance/baseline-diff sections.
4. **Scan progress** — always-on stderr summary + walker heartbeat + pass boundary events + --quiet flag.

Spec: `docs/superpowers/specs/2026-05-25-cbom-export-quality-design.md`
Plan: `docs/superpowers/plans/2026-05-25-cbom-export-quality.md`
ADR: `docs/decisions/ADR-040-library-asset-type.md`

## Breaking changes (CHANGELOG)

- `assetType: "library"` → `component.type: "library"` (no cryptoProperties)
- `primitive: "HARDCODED-SECRET"` → `assetType: related-crypto-material` with `materialType: "other"`
- Deprecated PQC names (Kyber/Dilithium/SPHINCS+/Falcon) silently mapped to canonical (ML-KEM/ML-DSA/SLH-DSA/FN-DSA)

## Test plan

- [x] `go test ./...` clean per commit
- [x] `--validate` passes on all 7 benchmark corpus scans
- [x] Manual PDF visual review for Option-D layout
- [x] All 4 duplication-avoidance scenarios for stderr summary
EOF
)"
```

---

# Self-Review (run after writing this plan)

This section is for the plan author. Engineers executing the plan can skip.

## Spec coverage

| Spec section | Plan task |
|---|---|
| Goal §1 (validation) | Tasks 1.1-1.8 |
| Goal §2 (quantum) | Tasks 2.1-2.4 |
| Goal §3 (PDF) | Tasks 3.0-3.10 |
| Work item 4 (progress + summary) | Tasks 4.1-4.5 |
| Closed-set tally + --strict-validate | Tasks 1.1, 1.5 |
| Asset rerouting (HARDCODED-SECRET) | Task 1.2 |
| Library handling (ADR-040) | Tasks 1.3, 1.7 |
| Source-side cleanup of config_scanner | Task 1.6 |
| YAML schema + embedded table | Task 2.2 |
| normalizeFamily fuzzy matching | Task 2.2 |
| QuantumNotApplicable + omit-on-render | Tasks 2.1, 2.3 |
| go-echarts dep | Task 3.0 |
| Aggregate() + breakdowns | Task 3.3 |
| Quantum migration backlog table | Task 3.5 |
| Charts (or fallback) | Task 3.6 |
| Compliance section (stub) | Task 3.7 |
| --baseline diff | Task 3.8 |
| Walker heartbeat | Tasks 4.1, 4.3 |
| Pass boundary events | Task 4.3 |
| Always-on final summary | Task 4.2 |
| Duplication-avoidance rule | Task 4.2 (truth-table test) |

All spec sections covered.

## Placeholder scan

- Task 3.7 (compliance section) is an intentional stub — flagged inline with the rationale that `types.ScanResult` doesn't yet have a stable `ComplianceResults` field. This is documented in the task body.
- Task 3.6 (charts) has a conditional fallback ("if go-echarts can't produce PNG server-side without a browser") — the fallback is documented (maroto-native bar). Engineer must verify during implementation; if fallback is needed, the renderer call site doesn't change.
- All other tasks have concrete code blocks.

## Type consistency

- `validationTally` defined in Task 1.1; used by Tasks 1.2, 1.3, 1.4, 1.5. Field names consistent.
- `SummaryStats`, `KV` defined in Task 3.3; used by Task 3.6 (charts).
- `BacklogEntry` defined in Task 3.5.
- `ResolvedOutput` defined in Task 4.2; used by Task 4.4.
- `ProgressOpts`, `progressEmitter`, `newProgressEmitter` consistent across Tasks 4.1, 4.3, 4.4.
- `pdf.Options{Baseline}` defined in Task 3.1; used by Task 3.8.

No type drift detected.

## Scope check

Plan is focused on the 4 work items from one spec. Single PR. ~3,000 LOC estimated total. Within range for a coherent code review.
