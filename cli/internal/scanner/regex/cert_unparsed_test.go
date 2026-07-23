package regex

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// makeSelfSignedDER returns the DER and PEM encodings of a throwaway cert.
func makeSelfSignedDER(t *testing.T) (der, pemBytes []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "unparsed-test.example.com"},
		NotBefore:    nb,
		NotAfter:     nb.AddDate(1, 0, 0),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return der, pemBytes
}

func countUnparsed(findings []types.Finding) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == "cbom-cert-unparsed" {
			n++
		}
	}
	return n
}

func TestUnparsedDERCert(t *testing.T) {
	s := New()
	// A .der file that is not a valid DER certificate must be surfaced, not dropped.
	findings, err := s.ScanFile("broken.der", []byte("this is not a certificate, just opaque bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if countUnparsed(findings) != 1 {
		t.Fatalf("expected 1 unparsed-cert finding, got %d (%d total)", countUnparsed(findings), len(findings))
	}
	f := findings[0]
	if f.AssetType != types.AssetCertificate || f.Properties.CertificateFormat != "DER" {
		t.Errorf("unexpected finding: type=%s format=%s", f.AssetType, f.Properties.CertificateFormat)
	}
}

func TestUnparsedPKCS7(t *testing.T) {
	s := New()
	findings, err := s.ScanFile("broken.p7b", []byte("definitely not a pkcs7 bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if countUnparsed(findings) != 1 {
		t.Fatalf("expected 1 unparsed-cert finding, got %d", countUnparsed(findings))
	}
	if findings[0].Properties.CertificateFormat != "PKCS7" {
		t.Errorf("format = %q, want PKCS7", findings[0].Properties.CertificateFormat)
	}
}

func TestValidDERCertNotFlaggedUnparsed(t *testing.T) {
	s := New()
	der, _ := makeSelfSignedDER(t)
	findings, err := s.ScanFile("good.der", der)
	if err != nil {
		t.Fatal(err)
	}
	if countUnparsed(findings) != 0 {
		t.Errorf("valid DER cert should not be flagged unparsed, got %d", countUnparsed(findings))
	}
	parsed := false
	for _, f := range findings {
		if f.AssetType == types.AssetCertificate && f.Properties.SubjectName != "" {
			parsed = true
		}
	}
	if !parsed {
		t.Error("expected a parsed X.509 certificate finding with a subject")
	}
}

func TestPEMCrtStillParses(t *testing.T) {
	s := New()
	_, pemBytes := makeSelfSignedDER(t)
	// A PEM-encoded .crt must fall through to the text path and parse — not be
	// flagged as unparsed DER.
	findings, err := s.ScanFile("cert.crt", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if countUnparsed(findings) != 0 {
		t.Errorf("PEM .crt should parse via the text path, got %d unparsed", countUnparsed(findings))
	}
	parsed := false
	for _, f := range findings {
		if f.AssetType == types.AssetCertificate && f.Properties.SubjectName != "" {
			parsed = true
		}
	}
	if !parsed {
		t.Error("expected the PEM .crt to yield a parsed certificate finding")
	}
}
