// Package keystore scans Java KeyStore (JKS) and PKCS#12 (.p12/.pfx) keystore
// files. It enumerates the certificates inside (full crypto inventory) and, when
// a keystore opens with a well-known default or weak password, also flags that
// as a security finding. Keystores that stay locked are still reported with
// their path so they appear in the inventory.
//
// The default password set is curated from common keystore defaults (JDK
// `changeit`, Android `android`, GCP `notasecret`, WebLogic demo stores, …) plus
// a list shared from a prior SonarQube cert-expiry plugin. Users can extend it
// with `--keystore-wordlist`.
package keystore

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/nk-sentinel/cipherradar/cli/internal/scanner"
	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

var findingCounter atomic.Int64

func nextID() string { return fmt.Sprintf("KEYSTORE-%04d", findingCounter.Add(1)) }

// defaultPasswords is the curated default/weak keystore password set (researched
// platform defaults + a shared SonarQube plugin list). PKCS12 enforces a 6-char
// minimum, so shorter entries apply to JKS only.
var defaultPasswords = []string{
	"", "changeit", "changeme", "password", "keystorepass", "keystore",
	"storepass", "trustpass", "truststorepass", "123456", "secret", "default",
	"p@ssw0rd", "WebAS", "android", "notasecret",
	"DemoIdentityKeyStorePassPhrase", "DemoTrustKeyStorePassPhrase",
}

// userWordlist holds extra passwords supplied via --keystore-wordlist. It is set
// once at startup before scanning begins.
var userWordlist []string

// SetUserWordlist registers additional candidate passwords (from
// --keystore-wordlist). Called once before scanning.
func SetUserWordlist(words []string) { userWordlist = words }

// harvestedPasswords holds candidate passwords discovered by the source/config
// harvest pass (issue #92). Set once before scanning; used only as open
// candidates and never reported.
var harvestedPasswords []string

// SetHarvestedPasswords registers passwords harvested from project config/source
// (see HarvestPasswords). Tried after the default set and filename guesses, so a
// keystore that opens on a default never incurs their cost (lazy escalation).
func SetHarvestedPasswords(words []string) { harvestedPasswords = words }

// Scanner detects and inspects keystore files.
type Scanner struct{}

// New creates a keystore Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the scanner name.
func (s *Scanner) Name() string { return "keystore" }

// Extensions returns the keystore file extensions handled.
func (s *Scanner) Extensions() []string {
	return []string{".jks", ".keystore", ".p12", ".pfx", ".bks", ".jceks", ".bcfks", ".truststore"}
}

// ScanFile inspects a keystore file's bytes.
func (s *Scanner) ScanFile(path string, content []byte) ([]types.Finding, error) {
	if len(content) == 0 {
		return nil, nil
	}
	candidates := passwordCandidates(path)
	ext := strings.ToLower(filepath.Ext(path))

	// BCFKS (BouncyCastle FIPS): the whole store is encrypted, so its
	// certificates cannot be enumerated without the store password + a BC
	// implementation (tracked in #94). Capture its presence honestly rather than
	// leaving it invisible to the inventory.
	if ext == ".bcfks" {
		return scanner.AnnotateFindings([]types.Finding{
			keystorePresenceFinding(path, ext, false, false, reasonUnsupported),
		}), nil
	}

	// BKS (BouncyCastle): its store data is plaintext, so enumerate certificates
	// directly. Key/secret/sealed blobs are length-prefixed and skipped; no
	// password is needed for cert reading.
	if ext == ".bks" {
		certs, hasPrivateKey, opened := openBKS(content)
		findings := []types.Finding{keystorePresenceFinding(path, ext, opened, hasPrivateKey, reasonUnsupported)}
		for _, c := range certs {
			findings = append(findings, buildKeystoreCertFinding(c, path))
		}
		return scanner.AnnotateFindings(findings), nil
	}

	// JCEKS: keystore-go rejects its magic number, but its certificate entries
	// are plaintext DER, so enumerate them directly (no password needed). No
	// weak-password check — no password is matched for cert reading.
	if ext == ".jceks" {
		certs, hasPrivateKey, opened := openJCEKS(content)
		findings := []types.Finding{keystorePresenceFinding(path, ext, opened, hasPrivateKey, reasonUnsupported)}
		for _, c := range certs {
			findings = append(findings, buildKeystoreCertFinding(c, path))
		}
		return scanner.AnnotateFindings(findings), nil
	}

	var certs []*x509.Certificate
	var matchedPwd string
	var opened, hasPrivateKey bool

	switch ext {
	case ".p12", ".pfx":
		certs, matchedPwd, opened = openPKCS12(content, candidates)
		hasPrivateKey = opened // DecodeChain implies a key entry was present
	default: // .jks, .keystore, .truststore (best effort via JKS loader)
		certs, matchedPwd, opened, hasPrivateKey = openJKS(content, candidates)
	}

	findings := []types.Finding{keystorePresenceFinding(path, ext, opened, hasPrivateKey, reasonLocked)}

	if !opened {
		return scanner.AnnotateFindings(findings), nil
	}

	// Inventory each embedded certificate via the same modeling as file certs.
	for _, c := range certs {
		findings = append(findings, buildKeystoreCertFinding(c, path))
	}

	// A keystore that opened with a known default/weak password is a finding.
	if isWeakPassword(matchedPwd, path) {
		findings = append(findings, weakPasswordFinding(path, matchedPwd))
	}
	return scanner.AnnotateFindings(findings), nil
}

// passwordCandidates returns the default list plus filename-derived guesses and
// any user-supplied wordlist.
func passwordCandidates(path string) []string {
	base := filepath.Base(path)
	nameNoExt := strings.TrimSuffix(base, filepath.Ext(base))
	cands := make([]string, 0, len(defaultPasswords)+len(userWordlist)+len(harvestedPasswords)+2)
	// Order matters: cheap, common defaults first so a keystore that opens on a
	// default never reaches the filename/harvested/user candidates. This is the
	// lazy-escalation guarantee — harvested passwords cost open attempts only on
	// keystores still locked after the defaults.
	cands = append(cands, defaultPasswords...)
	cands = append(cands, base, nameNoExt)
	cands = append(cands, harvestedPasswords...)
	cands = append(cands, userWordlist...)
	return cands
}

// openPKCS12 tries each candidate password against a PKCS#12 blob, returning the
// certificates, the password that worked, and whether it opened.
func openPKCS12(content []byte, candidates []string) ([]*x509.Certificate, string, bool) {
	for _, pw := range candidates {
		// DecodeChain returns key + leaf + CAs; fall back to trust store (cert-only).
		if _, leaf, ca, err := pkcs12.DecodeChain(content, pw); err == nil {
			certs := ca
			if leaf != nil {
				certs = append([]*x509.Certificate{leaf}, ca...)
			}
			return certs, pw, true
		}
		if certs, err := pkcs12.DecodeTrustStore(content, pw); err == nil {
			return certs, pw, true
		}
	}
	return nil, "", false
}

// openJKS tries each candidate password against a JKS store. The store password
// is required for the integrity check; trusted-cert entries are then readable
// without per-entry passwords.
func openJKS(content []byte, candidates []string) ([]*x509.Certificate, string, bool, bool) {
	for _, pw := range candidates {
		ks := jks.New()
		if err := ks.Load(bytes.NewReader(content), []byte(pw)); err != nil {
			continue
		}
		var certs []*x509.Certificate
		hasKey := false
		for _, alias := range ks.Aliases() {
			if ks.IsPrivateKeyEntry(alias) {
				hasKey = true
				if chain, err := ks.GetPrivateKeyEntryCertificateChain(alias); err == nil {
					certs = append(certs, parseJKSCerts(chain)...)
				}
				continue
			}
			if entry, err := ks.GetTrustedCertificateEntry(alias); err == nil {
				if c, perr := x509.ParseCertificate(entry.Certificate.Content); perr == nil {
					certs = append(certs, c)
				}
			}
		}
		return certs, pw, true, hasKey
	}
	return nil, "", false, false
}

func parseJKSCerts(chain []jks.Certificate) []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range chain {
		if parsed, err := x509.ParseCertificate(c.Content); err == nil {
			out = append(out, parsed)
		}
	}
	return out
}

// isWeakPassword reports whether the password that opened a keystore is a
// well-known default / weak value (anything in the curated list, or the
// filename). An empty password always counts as weak.
func isWeakPassword(pw, path string) bool {
	for _, d := range defaultPasswords {
		if pw == d {
			return true
		}
	}
	base := filepath.Base(path)
	return pw == base || pw == strings.TrimSuffix(base, filepath.Ext(base))
}
