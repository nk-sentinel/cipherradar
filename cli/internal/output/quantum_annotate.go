package output

import (
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/quantum"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// curveTokenFamily maps elliptic-curve / signature-variant canonical primitive
// tokens (as emitted by OpenGrep rule cbom-primitive metadata) to the algorithm
// family key recognised by quantum.GetInfo. These tokens do not normalise to a
// table family on their own (e.g. "P-256" suffix-strips to "p", "CURVE25519" to
// "curve"), so we resolve them explicitly. All entries here are classical
// elliptic-curve assets that Shor's algorithm breaks — they resolve to a
// quantum-vulnerable family.
//
// Tokens NOT listed here fall through to quantum.GetInfo(token) directly, which
// already resolves the common shapes (ELGAMAL, ED448, ECDSA, RSA, AES-256-GCM,
// ML-KEM, SHA-256, …) via its alias table and suffix-stripping. Anything that
// quantum.GetInfo cannot classify is left unlabeled (conservative: no guesses,
// no false positives).
var curveTokenFamily = map[string]string{
	// NIST P-curves used for ECDSA / ECDH.
	"P-192": "ec", "P-224": "ec", "P-256": "ec", "P-384": "ec", "P-521": "ec",
	// SECP / SEC1 curve names (forward-compat with rules that emit them).
	"SECP192R1": "ec", "SECP224R1": "ec", "SECP256R1": "ec",
	"SECP256K1": "ec", "SECP384R1": "ec", "SECP521R1": "ec",
	// Brainpool curves (forward-compat).
	"BRAINPOOLP256R1": "ec", "BRAINPOOLP384R1": "ec", "BRAINPOOLP512R1": "ec",
	// Curve25519 / Ed25519 family variants.
	"CURVE25519": "ed25519", "ED25519PH": "ed25519", "ED25519CTX": "ed25519",
	"CURVE448": "ed448",
}

// resolveQuantumFamily returns the algorithm-family key to feed quantum.GetInfo
// for a finding's crypto properties. It prefers an explicit AlgorithmFamily; if
// that is empty (the common Pass-2/OpenGrep case, where only AlgorithmPrimitive
// is populated), it derives a family from the canonical primitive token: first
// via the curveTokenFamily map, otherwise the token itself (GetInfo handles
// alias resolution and suffix-stripping). Returns "" when nothing resolvable.
func resolveQuantumFamily(p *types.CryptoProperties) string {
	if fam := strings.TrimSpace(p.AlgorithmFamily); fam != "" {
		return fam
	}
	tok := strings.TrimSpace(p.AlgorithmPrimitive)
	if tok == "" {
		return ""
	}
	if fam, ok := curveTokenFamily[strings.ToUpper(tok)]; ok {
		return fam
	}
	return tok
}

// effectiveAssetTypeFor mirrors convertCryptoProperties' reroute logic so the
// quantum annotator classifies a finding against the SAME asset type the CBOM
// converter will ultimately emit. A reroute marker in AlgorithmPrimitive
// (e.g. TLS-1.2 → protocol, PRIVATE-KEY-PEM → related-crypto-material) moves the
// finding off the algorithm axis, so it must not be quantum-labeled.
func effectiveAssetTypeFor(f *types.Finding) types.AssetType {
	if f.Properties.AlgorithmPrimitive != "" {
		if at, _ := rerouteMarker(f.Properties.AlgorithmPrimitive); at != "" {
			return at
		}
	}
	return f.AssetType
}

// AnnotateQuantum stamps quantum posture onto every finding in the scan result
// that has a resolvable algorithm family but no posture yet (the Pass-2 /
// OpenGrep case). It is the single shared pipeline step that closes issue #30,
// and is safe to call more than once (the per-finding guard makes it
// idempotent). Run it once after scan finalization so every output format —
// CBOM, text, SARIF, PDF, policy — sees identical quantum labels.
func AnnotateQuantum(result *types.ScanResult) {
	if result == nil {
		return
	}
	for i := range result.Findings {
		annotateQuantum(&result.Findings[i])
	}
}

// annotateQuantum stamps QuantumStatus + NistQuantumLevel onto a finding that
// has a resolvable algorithm family but no quantum posture yet. This is the
// single shared point that closes issue #30: Pass-1 AST scanners already call
// quantum.GetInfo at emit time, but Pass-2 (OpenGrep) findings reach the
// converter unlabeled. Running every finding through here gives both passes
// identical quantum posture.
//
// Invariants:
//   - Findings already labeled by Pass-1 (QuantumStatus set, or a non-zero
//     NistQuantumLevel) are left untouched — zero regressions.
//   - Non-algorithm asset types (certificate, related-crypto-material, library)
//     and reroute-marked findings are skipped via quantum.GetInfoForAsset, which
//     returns not-applicable for them — they stay blank, per #30 scope.
//   - Findings with no resolved family (jca-cipher-getinstance,
//     cipher-spec-inventory, CSPRNG, …) or a family quantum.GetInfo cannot
//     classify stay blank — no guesses, zero new false positives.
func annotateQuantum(f *types.Finding) {
	// Preserve any posture a scanner already attached (Pass-1 path).
	if f.Properties.QuantumStatus != "" || f.Properties.NistQuantumLevel != 0 {
		return
	}

	family := resolveQuantumFamily(&f.Properties)
	if family == "" {
		return
	}

	// Use the effective (post-reroute) asset type so non-algorithm assets are
	// excluded exactly as the converter excludes them.
	assetType := string(effectiveAssetTypeFor(f))
	info := quantum.GetInfoForAsset(family, assetType)

	// quantum.GetInfo strips numeric key-size suffixes (AES-256-GCM → aes) but
	// not alphabetic mode/wrap suffixes (AES-ECB, AES-KW). When the full token
	// doesn't resolve, retry with the leading algorithm segment so a known
	// family + mode still inherits its family's posture (AES-ECB → aes →
	// quantum-safe). Tokens whose prefix is also unknown (NTRU, CLASSIC-MCELIECE,
	// KECCAK-256, ISO9796-2) remain unresolved and stay blank.
	if info.Status == types.QuantumUnknown {
		if idx := strings.Index(family, "-"); idx > 0 {
			if base := quantum.GetInfoForAsset(family[:idx], assetType); base.Status != types.QuantumUnknown {
				info = base
			}
		}
	}

	// Only stamp a definitive posture. QuantumUnknown / QuantumNotApplicable
	// carry no information and would only add noise (and a misleading
	// quantumStatus=quantum-unknown property), so leave those findings blank.
	switch info.Status {
	case types.QuantumVulnerable, types.QuantumSafe, types.Broken:
		f.Properties.QuantumStatus = info.Status
		f.Properties.NistQuantumLevel = info.NistLevel
	}
}
