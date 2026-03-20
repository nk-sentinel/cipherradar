package configfile

import (
	"os"
	"testing"
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
