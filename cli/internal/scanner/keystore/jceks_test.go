package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func makeDER(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func u32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func utfb(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func jceksHeader(magic, version, count uint32) []byte {
	var b bytes.Buffer
	b.Write(u32b(magic))
	b.Write(u32b(version))
	b.Write(u32b(count))
	return b.Bytes()
}

func trustedCertEntry(alias string, der []byte) []byte {
	var b bytes.Buffer
	b.Write(u32b(2)) // tag: trusted cert
	b.Write(utfb(alias))
	b.Write(make([]byte, 8)) // timestamp
	b.Write(utfb("X.509"))   // cert type (version 2)
	b.Write(u32b(uint32(len(der))))
	b.Write(der)
	return b.Bytes()
}

func privateKeyEntry(alias string, der []byte) []byte {
	var b bytes.Buffer
	b.Write(u32b(1)) // tag: private key
	b.Write(utfb(alias))
	b.Write(make([]byte, 8))
	key := []byte("encrypted-key-blob")
	b.Write(u32b(uint32(len(key))))
	b.Write(key)
	b.Write(u32b(1)) // chain length
	b.Write(utfb("X.509"))
	b.Write(u32b(uint32(len(der))))
	b.Write(der)
	return b.Bytes()
}

func TestOpenJCEKS_TrustedCert(t *testing.T) {
	der := makeDER(t, "trusted.example.com")
	var b bytes.Buffer
	b.Write(jceksHeader(magicJCEKS, 2, 1))
	b.Write(trustedCertEntry("mycert", der))
	b.Write(make([]byte, 20)) // trailing integrity digest (ignored)

	certs, hasKey, opened := openJCEKS(b.Bytes())
	if !opened {
		t.Fatal("expected opened=true")
	}
	if hasKey {
		t.Error("trusted-cert-only store should report hasPrivateKey=false")
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "trusted.example.com" {
		t.Fatalf("got %d certs, want 1 (trusted.example.com)", len(certs))
	}
}

func TestOpenJCEKS_PrivateKeyChain(t *testing.T) {
	der := makeDER(t, "leaf.example.com")
	var b bytes.Buffer
	b.Write(jceksHeader(magicJCEKS, 2, 1))
	b.Write(privateKeyEntry("key1", der))

	certs, hasKey, opened := openJCEKS(b.Bytes())
	if !opened || !hasKey || len(certs) != 1 {
		t.Fatalf("opened=%v hasKey=%v certs=%d, want true/true/1", opened, hasKey, len(certs))
	}
	if certs[0].Subject.CommonName != "leaf.example.com" {
		t.Errorf("cn = %q", certs[0].Subject.CommonName)
	}
}

func TestOpenJCEKS_BadMagicNotOpened(t *testing.T) {
	if _, _, opened := openJCEKS([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 2}); opened {
		t.Error("bad magic must not open")
	}
}

func TestOpenJCEKS_TruncatedNoPanic(t *testing.T) {
	// Header claims 5 entries but the buffer ends — must not panic.
	certs, _, opened := openJCEKS(jceksHeader(magicJCEKS, 2, 5))
	if !opened {
		t.Error("valid header -> opened")
	}
	if len(certs) != 0 {
		t.Errorf("no certs expected in truncated store, got %d", len(certs))
	}
}

func TestOpenJCEKS_SecretKeyStopsGracefully(t *testing.T) {
	der := makeDER(t, "before.example.com")
	var b bytes.Buffer
	b.Write(jceksHeader(magicJCEKS, 2, 2))
	b.Write(trustedCertEntry("c1", der))
	// Tag-3 secret-key entry (no length-prefixed body): parser must stop here.
	b.Write(u32b(3))
	b.Write(utfb("secret"))
	b.Write(make([]byte, 8))
	b.Write([]byte("unparseable-sealed-object"))

	certs, _, opened := openJCEKS(b.Bytes())
	if !opened || len(certs) != 1 {
		t.Fatalf("opened=%v certs=%d, want the 1 cert before the secret-key entry", opened, len(certs))
	}
}

func TestScanFile_JCEKSRouting(t *testing.T) {
	der := makeDER(t, "routed.example.com")
	var b bytes.Buffer
	b.Write(jceksHeader(magicJCEKS, 2, 1))
	b.Write(trustedCertEntry("c", der))

	findings, err := New().ScanFile("store.jceks", b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var sawCert, sawPresence bool
	for _, f := range findings {
		if f.AssetType == types.AssetCertificate && f.Properties.SubjectName != "" {
			sawCert = true
		}
		if strings.Contains(strings.ToLower(f.Name), "keystore") {
			sawPresence = true
		}
	}
	if !sawCert {
		t.Error("expected a certificate finding from the JCEKS store")
	}
	if !sawPresence {
		t.Error("expected a keystore presence finding")
	}
}
