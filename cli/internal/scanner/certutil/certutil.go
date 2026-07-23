// Package certutil builds CycloneDX-ready certificate findings from parsed
// X.509 certificates. It is shared by the regex scanner (PEM/DER certs in
// source) and the keystore scanner (certs inside JKS/PKCS#12 stores) so both
// produce identically-modeled certificate findings (subject/issuer/validity,
// signature + public-key algorithm, X.509 extensions) that the converter
// decomposes into a linked dependency graph.
package certutil

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // needed to type-switch DSA public keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// BuildFinding constructs a certificate finding from a parsed cert. idFn supplies
// a unique finding ID, ruleID/format identify the source, and snippet is the
// location snippet (e.g. a PEM header or a keystore alias). lineNum is 1 for
// binary sources.
func BuildFinding(cert *x509.Certificate, path string, lineNum int, idFn func() string, ruleID, format, snippet, descPrefix string) types.Finding {
	severity := types.SeverityInfo
	state := "active"
	category := types.CategoryInventory
	now := time.Now()
	if now.After(cert.NotAfter) {
		severity, state, category = types.SeverityHigh, "expired", types.CategorySecurity
	} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
		severity, state, category = types.SeverityMedium, "expiring-soon", types.CategorySecurity
	}

	sigAlgo := cert.SignatureAlgorithm.String()
	pubAlgo, pubSize := PublicKeyInfo(cert)
	curve, exponent := PublicKeyExtras(cert)

	validityDays := 0
	if cert.NotAfter.After(cert.NotBefore) {
		validityDays = int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	}

	return types.Finding{
		ID:        idFn(),
		AssetType: types.AssetCertificate,
		Name:      fmt.Sprintf("X.509 Certificate (%s)", cert.Subject.CommonName),
		Location: types.Location{
			File: path, StartLine: lineNum, StartCol: 1, EndLine: lineNum, EndCol: 1,
			Snippet: snippet,
		},
		Severity:   severity,
		Confidence: types.ConfidenceHigh,
		Properties: types.CryptoProperties{
			SubjectName:               cert.Subject.String(),
			IssuerName:                cert.Issuer.String(),
			NotValidBefore:            cert.NotBefore.Format(time.RFC3339),
			NotValidAfter:             cert.NotAfter.Format(time.RFC3339),
			SignatureAlgorithm:        sigAlgo,
			CertificateFormat:         format,
			SubjectPublicKeyAlgorithm: pubAlgo,
			SubjectPublicKeySize:      pubSize,
			CertificateExtensions:     ExtensionSummaries(cert),
			State:                     state,
			AlgorithmPrimitive:        "CERTIFICATE-X509",
			SerialNumber:              SerialHex(cert.SerialNumber),
			FingerprintSHA256:         FingerprintSHA256(cert),
			SubjectKeyID:              hexColon(cert.SubjectKeyId),
			AuthorityKeyID:            hexColon(cert.AuthorityKeyId),
			CertificateVersion:        cert.Version,
			SelfSigned:                IsSelfSigned(cert),
			PublicKeyCurve:            curve,
			PublicKeyExponent:         exponent,
			SignatureHash:             SignatureHashName(cert.SignatureAlgorithm),
			OCSPServers:               cert.OCSPServer,
			CAIssuerURLs:              cert.IssuingCertificateURL,
			CRLDistributionPoints:     cert.CRLDistributionPoints,
			CertificatePolicies:       policyOIDs(cert),
			ValidityDays:              validityDays,
		},
		Description: fmt.Sprintf("%s%q signed with %s (expires %s)",
			descPrefix, cert.Subject.CommonName, sigAlgo, cert.NotAfter.Format("2006-01-02")),
		RuleID:   ruleID,
		Category: category,
		Maturity: types.MaturityStable,
		Pass:     1,
	}
}

// PublicKeyInfo returns the certificate's public-key algorithm name and size in
// bits, derived directly from the parsed key.
func PublicKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *dsa.PublicKey:
		if pub.P != nil {
			return "DSA", pub.P.BitLen()
		}
		return "DSA", 0
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// PublicKeyExtras returns the named curve (for EC/Ed keys) and the RSA public
// exponent (0 for non-RSA), complementing the algorithm/size from PublicKeyInfo.
func PublicKeyExtras(cert *x509.Certificate) (curve string, exponent int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "", pub.E
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return pub.Curve.Params().Name, 0
		}
	case ed25519.PublicKey:
		return "Ed25519", 0
	}
	return "", 0
}

// FingerprintSHA256 returns the lowercase colon-separated hex SHA-256 over the
// certificate DER — the canonical identity/dedup key.
func FingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hexColon(sum[:])
}

// SerialHex renders a certificate serial number as colon-separated hex.
func SerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hexColon(b)
}

// IsSelfSigned reports whether the certificate is self-signed: subject and
// issuer DNs are byte-identical and the signature verifies against its own key.
func IsSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// SignatureHashName returns the hash used by a signature algorithm (e.g.
// "SHA-256", "SHA-1"), or "" when there is no distinct external hash (e.g.
// pure Ed25519). Surfaced so weak-hash signatures are easy to flag.
func SignatureHashName(sa x509.SignatureAlgorithm) string {
	switch sa {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1"
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return "SHA-256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return "SHA-384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return "SHA-512"
	default:
		return ""
	}
}

// policyOIDs renders the certificate policy OIDs as dotted-decimal strings.
func policyOIDs(cert *x509.Certificate) []string {
	if len(cert.Policies) == 0 {
		return nil
	}
	out := make([]string, 0, len(cert.Policies))
	for _, oid := range cert.Policies {
		out = append(out, oid.String())
	}
	return out
}

// hexColon renders bytes as lowercase colon-separated hex ("ab:cd:ef"); returns
// "" for empty input.
func hexColon(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := hex.EncodeToString(b)
	var sb strings.Builder
	sb.Grow(len(s) + len(b) - 1)
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(s[i : i+2])
	}
	return sb.String()
}

// ExtensionSummaries renders the security-relevant X.509 extensions (KeyUsage,
// ExtendedKeyUsage, BasicConstraints, SubjectAltName) as compact strings.
func ExtensionSummaries(cert *x509.Certificate) []string {
	var out []string
	if ku := keyUsageNames(cert.KeyUsage); len(ku) > 0 {
		out = append(out, "KeyUsage="+strings.Join(ku, ","))
	}
	if eku := extKeyUsageNames(cert.ExtKeyUsage); len(eku) > 0 {
		out = append(out, "ExtendedKeyUsage="+strings.Join(eku, ","))
	}
	if cert.BasicConstraintsValid {
		bc := "BasicConstraints=CA:false"
		if cert.IsCA {
			bc = "BasicConstraints=CA:true"
			if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
				bc += fmt.Sprintf(",pathlen:%d", cert.MaxPathLen)
			}
		}
		out = append(out, bc)
	}
	if san := subjectAltNames(cert); len(san) > 0 {
		out = append(out, "SubjectAltName="+strings.Join(san, ","))
	}
	return out
}

func keyUsageNames(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var names []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			names = append(names, p.name)
		}
	}
	return names
}

func extKeyUsageNames(ekus []x509.ExtKeyUsage) []string {
	name := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
		x509.ExtKeyUsageAny:             "any",
	}
	var names []string
	for _, e := range ekus {
		if n, ok := name[e]; ok {
			names = append(names, n)
		}
	}
	return names
}

func subjectAltNames(cert *x509.Certificate) []string {
	const maxSAN = 10
	var sans []string
	for _, d := range cert.DNSNames {
		sans = append(sans, "DNS:"+d)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, e := range cert.EmailAddresses {
		sans = append(sans, "email:"+e)
	}
	for _, u := range cert.URIs {
		sans = append(sans, "URI:"+u.String())
	}
	if len(sans) > maxSAN {
		extra := len(sans) - maxSAN
		sans = append(sans[:maxSAN], fmt.Sprintf("(+%d more)", extra))
	}
	return sans
}
