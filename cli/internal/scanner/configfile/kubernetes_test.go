package configfile

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestKubernetesName(t *testing.T) {
	s := NewKubernetes()
	if s.Name() != "kubernetes" {
		t.Errorf("expected name 'kubernetes', got %q", s.Name())
	}
}

func TestKubernetesExtensions(t *testing.T) {
	s := NewKubernetes()
	exts := s.Extensions()
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	expected := map[string]bool{".yaml": true, ".yml": true}
	for _, ext := range exts {
		if !expected[ext] {
			t.Errorf("unexpected extension %q", ext)
		}
	}
}

func TestKubernetesScanFile(t *testing.T) {
	content, err := os.ReadFile("../../../testdata/configfile/k8s-ingress.yaml")
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}

	s := NewKubernetes()
	findings, err := s.ScanFile("k8s-ingress.yaml", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Should detect TLS secret.
	assertHasFinding(t, findings, "Kubernetes TLS secret")

	// Should detect Ingress TLS secret reference.
	assertHasFinding(t, findings, "Ingress TLS secret:")

	// Should detect weak ciphers in annotation.
	assertHasFinding(t, findings, "Weak cipher in K8s annotation: RC4-SHA")
	assertHasFinding(t, findings, "Weak cipher in K8s annotation: DES-CBC3-SHA")

	// Should detect weak protocols in annotation.
	assertHasFinding(t, findings, "Weak TLS protocol in K8s annotation: TLSv1")
	assertHasFinding(t, findings, "Weak TLS protocol in K8s annotation: TLSv1.1")

	// All findings should have Pass=1.
	for _, f := range findings {
		if f.Pass != 1 {
			t.Errorf("expected Pass=1 for %q, got %d", f.Name, f.Pass)
		}
	}
}

func TestKubernetesNonK8sYAML(t *testing.T) {
	content := []byte(`
name: MyApp
version: "1.0"
description: A simple application
`)
	s := NewKubernetes()
	findings, err := s.ScanFile("app.yaml", content)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-K8s YAML, got %d", len(findings))
	}
}

func TestKubernetesEmptyFile(t *testing.T) {
	s := NewKubernetes()
	findings, err := s.ScanFile("empty.yaml", []byte{})
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty file, got %d", len(findings))
	}
}

func TestKubernetesSecretBase64Cert(t *testing.T) {
	// Generate a self-signed cert, PEM-encode, base64 it, embed in a TLS Secret.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "k8s.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemB := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b64 := base64.StdEncoding.EncodeToString(pemB)

	manifest := "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\nmetadata:\n  name: tls\ndata:\n  tls.crt: " + b64 + "\n"

	findings, err := NewKubernetes().ScanFile("secret.yaml", []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	var certF *types.Finding
	for i := range findings {
		if findings[i].RuleID == "cbom-configfile-k8s-cert" {
			certF = &findings[i]
		}
	}
	if certF == nil {
		t.Fatal("expected a decoded certificate finding from k8s secret data")
	}
	if certF.Properties.SubjectPublicKeyAlgorithm != "RSA" || certF.Properties.SubjectPublicKeySize != 2048 {
		t.Errorf("pubkey = %s/%d, want RSA/2048", certF.Properties.SubjectPublicKeyAlgorithm, certF.Properties.SubjectPublicKeySize)
	}
}
