package certutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func mustOID(t *testing.T, arcs ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(arcs)
	if err != nil {
		t.Fatalf("OIDFromInts: %v", err)
	}
	return oid
}

// selfSignedRSA builds a self-signed RSA cert with a broad set of extensions so
// every extracted field has a known expected value.
func selfSignedRSA(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Now().Add(-1 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x1234abcd),
		Subject:               pkix.Name{CommonName: "test.example.com", Organization: []string{"Example"}},
		NotBefore:             nb,
		NotAfter:              nb.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"test.example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"admin@example.com"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.example.com/crl.pem"},
		Policies:              []x509.OID{mustOID(t, 2, 23, 140, 1, 2, 1)},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
		// Go does not self-reference AKI on self-signed certs, so set it
		// explicitly to a distinct value to exercise AKI extraction.
		AuthorityKeyId: []byte{0x0a, 0x0b},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBuildFinding_RichMetadata(t *testing.T) {
	cert := selfSignedRSA(t)
	i := 0
	f := BuildFinding(cert, "certs/test.pem", 1, func() string { i++; return fmt.Sprintf("C-%d", i) },
		"cbom-cert", "PEM", "-----BEGIN CERTIFICATE-----", "")
	p := f.Properties

	strChecks := []struct{ name, got, want string }{
		{"serial", p.SerialNumber, "12:34:ab:cd"},
		{"subjectKeyID", p.SubjectKeyID, "01:02:03:04"},
		{"authorityKeyID", p.AuthorityKeyID, "0a:0b"},
		{"signatureHash", p.SignatureHash, "SHA-256"},
		{"publicKeyCurve", p.PublicKeyCurve, ""}, // RSA has no curve
	}
	for _, c := range strChecks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if p.FingerprintSHA256 == "" || p.FingerprintSHA256 != FingerprintSHA256(cert) {
		t.Errorf("fingerprint mismatch/empty: %q", p.FingerprintSHA256)
	}
	if want := 32*3 - 1; len(p.FingerprintSHA256) != want { // 32 bytes as colon-hex
		t.Errorf("fingerprint length = %d, want %d", len(p.FingerprintSHA256), want)
	}
	if !p.SelfSigned {
		t.Error("expected SelfSigned = true")
	}
	if p.CertificateVersion != 3 {
		t.Errorf("version = %d, want 3", p.CertificateVersion)
	}
	if p.PublicKeyExponent != 65537 {
		t.Errorf("exponent = %d, want 65537", p.PublicKeyExponent)
	}
	if want := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24); p.ValidityDays != want {
		t.Errorf("validityDays = %d, want %d", p.ValidityDays, want)
	}
	if len(p.OCSPServers) != 1 || p.OCSPServers[0] != "http://ocsp.example.com" {
		t.Errorf("ocspServers = %v", p.OCSPServers)
	}
	if len(p.CAIssuerURLs) != 1 || p.CAIssuerURLs[0] != "http://ca.example.com/ca.crt" {
		t.Errorf("caIssuerURLs = %v", p.CAIssuerURLs)
	}
	if len(p.CRLDistributionPoints) != 1 {
		t.Errorf("crlDistributionPoints = %v", p.CRLDistributionPoints)
	}
	if len(p.CertificatePolicies) != 1 || p.CertificatePolicies[0] != "2.23.140.1.2.1" {
		t.Errorf("certificatePolicies = %v", p.CertificatePolicies)
	}
	sawSAN := false
	for _, e := range p.CertificateExtensions {
		if strings.Contains(e, "SubjectAltName") {
			sawSAN = true
		}
	}
	if !sawSAN {
		t.Error("expected SubjectAltName in extensions")
	}
}

func TestBuildFinding_ECCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "ec.example.com"},
		NotBefore:          nb,
		NotAfter:           nb.AddDate(1, 0, 0),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := BuildFinding(cert, "ec.pem", 1, func() string { return "C-1" }, "r", "PEM", "", "")
	p := f.Properties
	if p.PublicKeyCurve != "P-256" {
		t.Errorf("curve = %q, want P-256", p.PublicKeyCurve)
	}
	if p.SubjectPublicKeyAlgorithm != "ECDSA" || p.SubjectPublicKeySize != 256 {
		t.Errorf("pubkey = %s/%d, want ECDSA/256", p.SubjectPublicKeyAlgorithm, p.SubjectPublicKeySize)
	}
	if p.SignatureHash != "SHA-384" {
		t.Errorf("signatureHash = %q, want SHA-384", p.SignatureHash)
	}
	if p.PublicKeyExponent != 0 {
		t.Errorf("exponent = %d, want 0 (EC)", p.PublicKeyExponent)
	}
}

func TestIsSelfSigned(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nb := time.Now().Add(-time.Hour)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root CA"},
		NotBefore: nb, NotAfter: nb.AddDate(2, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		SubjectKeyId: []byte{0x09, 0x09, 0x09},
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.example.com"},
		NotBefore: nb, NotAfter: nb.AddDate(1, 0, 0),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	if !IsSelfSigned(caCert) {
		t.Error("root CA should be self-signed")
	}
	if IsSelfSigned(leaf) {
		t.Error("CA-signed leaf should not be self-signed")
	}
}

func TestSerialHexAndHexColon(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want string
	}{
		{nil, ""},
		{big.NewInt(0), "00"},
		{big.NewInt(255), "ff"},
		{big.NewInt(0x1234), "12:34"},
	}
	for _, c := range cases {
		if got := SerialHex(c.in); got != c.want {
			t.Errorf("SerialHex(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := hexColon(nil); got != "" {
		t.Errorf("hexColon(nil) = %q, want empty", got)
	}
	if got := hexColon([]byte{0xde, 0xad, 0xbe, 0xef}); got != "de:ad:be:ef" {
		t.Errorf("hexColon = %q, want de:ad:be:ef", got)
	}
}

func TestSignatureHashName(t *testing.T) {
	cases := map[x509.SignatureAlgorithm]string{
		x509.SHA1WithRSA:     "SHA-1",
		x509.ECDSAWithSHA1:   "SHA-1",
		x509.ECDSAWithSHA256: "SHA-256",
		x509.SHA256WithRSA:   "SHA-256",
		x509.SHA384WithRSA:   "SHA-384",
		x509.SHA512WithRSA:   "SHA-512",
		x509.MD5WithRSA:      "MD5",
		x509.PureEd25519:     "",
	}
	for sa, want := range cases {
		if got := SignatureHashName(sa); got != want {
			t.Errorf("SignatureHashName(%v) = %q, want %q", sa, got, want)
		}
	}
}
