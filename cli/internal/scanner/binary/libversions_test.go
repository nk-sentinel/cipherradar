package binary

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func findByName(fs []types.Finding, name string) *types.Finding {
	for i := range fs {
		if fs[i].Name == name {
			return &fs[i]
		}
	}
	return nil
}

func TestScanLibraryVersions_ExtractsVersionAndPurl(t *testing.T) {
	content := []byte("\x00\x00 OpenSSL 3.0.1 14 Dec 2021 \x00 GnuTLS 3.7.2 \x00 Mbed TLS 3.1.0 \x00")
	fs := scanLibraryVersions("usr/lib/libcrypto.so", content)

	ossl := findByName(fs, "OpenSSL")
	if ossl == nil {
		t.Fatal("expected an OpenSSL fingerprint")
	}
	if ossl.AssetType != types.AssetLibrary {
		t.Errorf("AssetType = %q, want library", ossl.AssetType)
	}
	if ossl.Properties.LibraryVersion != "3.0.1" {
		t.Errorf("version = %q, want 3.0.1", ossl.Properties.LibraryVersion)
	}
	if ossl.Properties.LibraryPurl != "pkg:generic/openssl@3.0.1" {
		t.Errorf("purl = %q, want pkg:generic/openssl@3.0.1", ossl.Properties.LibraryPurl)
	}
	if ossl.Confidence != types.ConfidenceHigh {
		t.Errorf("confidence = %q, want high (version-string evidence)", ossl.Confidence)
	}

	if g := findByName(fs, "GnuTLS"); g == nil || g.Properties.LibraryVersion != "3.7.2" {
		t.Errorf("expected GnuTLS 3.7.2, got %+v", g)
	}
	if m := findByName(fs, "Mbed TLS"); m == nil || m.Properties.LibraryVersion != "3.1.0" {
		t.Errorf("expected Mbed TLS 3.1.0, got %+v", m)
	}
}

func TestScanLibraryVersions_BoringSSLHasNoVersion(t *testing.T) {
	fs := scanLibraryVersions("lib.so", []byte("prefix BoringSSL suffix"))
	b := findByName(fs, "BoringSSL")
	if b == nil {
		t.Fatal("expected BoringSSL fingerprint")
	}
	if b.Properties.LibraryVersion != "" {
		t.Errorf("BoringSSL should carry no version, got %q", b.Properties.LibraryVersion)
	}
	if b.Properties.LibraryPurl != "" {
		t.Errorf("no purl without a version, got %q", b.Properties.LibraryPurl)
	}
}

func TestScanLibraryVersions_NoMatch(t *testing.T) {
	if fs := scanLibraryVersions("x.so", []byte("nothing crypto here")); len(fs) != 0 {
		t.Errorf("expected no fingerprints, got %d", len(fs))
	}
}

func TestELFScanner_GoBuildInfoCryptoPackages(t *testing.T) {
	// Synthetic Go binary: the buildinfo magic + Go version + crypto package
	// import paths. extractGoBuildInfo works on raw bytes, so no real ELF needed.
	content := append([]byte(nil), goBuildInfoMagic...)
	content = append(content, []byte(" go1.21.5 ... crypto/aes ... crypto/tls ... ")...)

	fs, err := NewELFScanner().ScanFile("app", content)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	var aes, tls bool
	for _, f := range fs {
		if f.RuleID == "cbom-binary-go-aes" {
			aes = true
		}
		if f.RuleID == "cbom-binary-go-tls" {
			tls = true
		}
	}
	if !aes {
		t.Error("expected a Go crypto/aes finding from build-info")
	}
	if !tls {
		t.Error("expected a Go crypto/tls (protocol) finding from build-info")
	}
}
