package keystore

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner/certutil"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// keystoreTypeName returns a human label for a keystore file extension.
func keystoreTypeName(ext string) string {
	switch strings.ToLower(ext) {
	case ".p12", ".pfx":
		return "PKCS12"
	case ".jks", ".keystore":
		return "JKS"
	case ".bks":
		return "BKS"
	case ".truststore":
		return "truststore"
	default:
		return "keystore"
	}
}

// presenceReason explains why a keystore's contents were not enumerated.
type presenceReason int

const (
	reasonLocked      presenceReason = iota // password-protected, no candidate opened it
	reasonUnsupported                       // format not parseable in pure Go (e.g. BKS)
)

// keystorePresenceFinding records that a keystore file exists at path. It is
// always emitted (inventory + the fact that a keystore is committed is itself
// noteworthy). When the store could not be opened, reason explains why.
func keystorePresenceFinding(path, ext string, opened, hasPrivateKey bool, reason presenceReason) types.Finding {
	kind := keystoreTypeName(ext)
	desc := fmt.Sprintf("%s keystore present at %s", kind, path)
	severity := types.SeverityInfo
	category := types.CategoryInventory
	if !opened {
		switch reason {
		case reasonUnsupported:
			desc += " — format not parsed (no pure-Go parser); contents not enumerated"
		default:
			desc += " — content locked (password-protected; could not enumerate)"
		}
	} else if hasPrivateKey {
		desc += " — contains private-key material"
	}
	return types.Finding{
		ID:         nextID(),
		AssetType:  types.AssetRelatedCryptoMaterial,
		Name:       fmt.Sprintf("%s keystore", kind),
		Location:   types.Location{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1, Snippet: path},
		Severity:   severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			MaterialType:       "other",
			AlgorithmPrimitive: "KEYSTORE",
		},
		Description: desc,
		RuleID:      "cbom-keystore-present",
		Category:    category,
		Maturity:    types.MaturityStable,
		Pass:        1,
	}
}

// buildKeystoreCertFinding wraps a certificate found inside a keystore, reusing
// the shared cert modeling so it decomposes into the same linked graph as file
// certificates.
func buildKeystoreCertFinding(cert *x509.Certificate, path string) types.Finding {
	return certutil.BuildFinding(cert, path, 1, nextID,
		"cbom-keystore-certificate", "X.509", "(keystore entry)",
		"X.509 certificate (keystore entry) for ")
}

// weakPasswordFinding flags a keystore that opened with a well-known default or
// weak password — a real security issue regardless of the contents.
func weakPasswordFinding(path, pw string) types.Finding {
	shown := pw
	if shown == "" {
		shown = "(empty)"
	}
	return types.Finding{
		ID:         nextID(),
		AssetType:  types.AssetRelatedCryptoMaterial,
		Name:       "Weak keystore password",
		Location:   types.Location{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1, Snippet: path},
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			MaterialType:       "other",
			AlgorithmPrimitive: "WEAK-KEYSTORE-PASSWORD",
		},
		Description: fmt.Sprintf("Keystore at %s opened with a well-known/default password %q — set a strong, unique password", path, shown),
		RuleID:      "cbom-keystore-weak-password",
		Category:    types.CategorySecurity,
		Maturity:    types.MaturityStable,
		Pass:        1,
	}
}
