package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func testCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "ks.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, der
}

func makeJKS(t *testing.T, der []byte, password string) []byte {
	t.Helper()
	ks := jks.New()
	if err := ks.SetTrustedCertificateEntry("ca", jks.TrustedCertificateEntry{
		CreationTime: time.Now(),
		Certificate:  jks.Certificate{Type: "X.509", Content: der},
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makePKCS12(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, password string) []byte {
	t.Helper()
	data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func hasRule(findings []types.Finding, rule string) bool {
	for _, f := range findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func countCerts(findings []types.Finding) int {
	n := 0
	for _, f := range findings {
		if f.AssetType == types.AssetCertificate {
			n++
		}
	}
	return n
}

func TestJKS_DefaultPasswordOpensAndFlags(t *testing.T) {
	_, _, der := testCert(t)
	data := makeJKS(t, der, "changeit")

	findings, err := New().ScanFile("trust.jks", data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "cbom-keystore-present") {
		t.Error("expected keystore presence finding")
	}
	if countCerts(findings) != 1 {
		t.Errorf("expected 1 cert finding, got %d", countCerts(findings))
	}
	if !hasRule(findings, "cbom-keystore-weak-password") {
		t.Error("expected weak-password finding for 'changeit'")
	}
}

func TestPKCS12_DefaultPasswordOpensAndFlags(t *testing.T) {
	cert, key, _ := testCert(t)
	data := makePKCS12(t, cert, key, "changeit")

	findings, err := New().ScanFile("id.p12", data)
	if err != nil {
		t.Fatal(err)
	}
	if countCerts(findings) < 1 {
		t.Errorf("expected >=1 cert finding, got %d", countCerts(findings))
	}
	if !hasRule(findings, "cbom-keystore-weak-password") {
		t.Error("expected weak-password finding")
	}
}

func TestPKCS12_StrongPasswordStaysLocked(t *testing.T) {
	cert, key, _ := testCert(t)
	data := makePKCS12(t, cert, key, "S0me-Str0ng-Unguessable-P@ss-9912")

	findings, err := New().ScanFile("id.p12", data)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(findings, "cbom-keystore-present") {
		t.Error("expected keystore presence finding even when locked")
	}
	if countCerts(findings) != 0 {
		t.Errorf("locked keystore should yield no cert findings, got %d", countCerts(findings))
	}
	if hasRule(findings, "cbom-keystore-weak-password") {
		t.Error("strong password must not be flagged weak")
	}
}

func TestUserWordlistUnlocks(t *testing.T) {
	cert, key, _ := testCert(t)
	const pw = "Corp-Internal-KS-Pass-2026"
	data := makePKCS12(t, cert, key, pw)

	// Without the wordlist: stays locked.
	before, err := New().ScanFile("x.p12", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := countCerts(before); got != 0 {
		t.Fatalf("expected locked before wordlist, got %d certs", got)
	}
	// With the wordlist: opens and inventories the cert.
	SetUserWordlist([]string{pw})
	defer SetUserWordlist(nil)
	after, err := New().ScanFile("x.p12", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := countCerts(after); got != 1 {
		t.Errorf("expected 1 cert after wordlist unlock, got %d", got)
	}
}
