package binary

import (
	"fmt"
	"regexp"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// libraryFingerprint matches an embedded version banner of a native crypto
// library in a compiled binary. Matching a version STRING is higher-confidence
// evidence than a crypto-constant byte match (Syft-style binary classification):
// it identifies the concrete library and, usually, its exact version.
type libraryFingerprint struct {
	name     string         // display / CBOM component name
	purlName string         // pkg:generic/<purlName>@<version>
	re       *regexp.Regexp // submatch group 1 = version, when present
}

// libraryFingerprints are ordered; each library is reported at most once. The
// regexes anchor on the library's canonical version banner so they don't fire
// on incidental mentions.
var libraryFingerprints = []libraryFingerprint{
	{"OpenSSL", "openssl", regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+[a-z]?)`)},
	{"LibreSSL", "libressl", regexp.MustCompile(`LibreSSL (\d+\.\d+\.\d+)`)},
	{"BoringSSL", "boringssl", regexp.MustCompile(`BoringSSL`)},
	{"GnuTLS", "gnutls", regexp.MustCompile(`GnuTLS (\d+\.\d+\.\d+)`)},
	{"Mbed TLS", "mbedtls", regexp.MustCompile(`[Mm]bed ?TLS (\d+\.\d+\.\d+)`)},
	{"wolfSSL", "wolfssl", regexp.MustCompile(`wolfSSL (\d+\.\d+\.\d+)`)},
	{"libsodium", "libsodium", regexp.MustCompile(`libsodium (\d+\.\d+\.\d+)`)},
	{"NSS", "nss", regexp.MustCompile(`NSS (\d+\.\d+(?:\.\d+)?)`)},
}

// scanLibraryVersions fingerprints statically-linked crypto libraries by their
// embedded version banners and emits CBOM library components (ADR-040). This is
// the highest-confidence rung of the binary detection ladder — a matched
// version string beats a symbol match, which beats a raw crypto-constant match.
func scanLibraryVersions(path string, content []byte) []types.Finding {
	var findings []types.Finding
	for _, fp := range libraryFingerprints {
		loc := fp.re.FindSubmatchIndex(content)
		if loc == nil {
			continue
		}
		version := ""
		if len(loc) >= 4 && loc[2] >= 0 {
			version = string(content[loc[2]:loc[3]])
		}

		props := types.CryptoProperties{Library: fp.name}
		desc := fmt.Sprintf("%s detected in binary (embedded version banner)", fp.name)
		if version != "" {
			props.LibraryVersion = version
			props.LibraryPurl = fmt.Sprintf("pkg:generic/%s@%s", fp.purlName, version)
			desc = fmt.Sprintf("%s %s statically linked (version banner)", fp.name, version)
		}

		findings = append(findings, types.Finding{
			ID:          nextFindingID(),
			AssetType:   types.AssetLibrary,
			Name:        fp.name,
			Location:    binaryLocation(path, loc[0], fp.name),
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidenceHigh, // version-string = strongest binary evidence
			Properties:  props,
			Description: desc,
			RuleID:      "cbom-binary-lib-" + fp.purlName,
			Pass:        1,
		})
	}
	return findings
}
