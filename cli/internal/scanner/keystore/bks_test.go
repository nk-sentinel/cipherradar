package keystore

import (
	"bytes"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// bksData writes a 4-byte-length-prefixed blob.
func bksData(b []byte) []byte {
	return append(u32b(uint32(len(b))), b...)
}

// bksHeader writes version + salt + iterationCount.
func bksHeader(version uint32) []byte {
	var out bytes.Buffer
	out.Write(u32b(version))
	out.Write(bksData(make([]byte, 20))) // salt
	out.Write(u32b(10000))               // iteration count
	return out.Bytes()
}

// bksCertRecord writes a (certType utf + certData) record.
func bksCertRecord(der []byte) []byte {
	var out bytes.Buffer
	out.Write(utfb("X.509"))
	out.Write(bksData(der))
	return out.Bytes()
}

func TestOpenBKS_CertEntryAndKeyChain(t *testing.T) {
	leaf := makeDER(t, "bks-leaf.example.com")
	chain := makeDER(t, "bks-ca.example.com")

	var b bytes.Buffer
	b.Write(bksHeader(2))

	// Entry 1: CERTIFICATE (type 1), no chain, one trailing cert.
	b.WriteByte(1)
	b.Write(utfb("cert-alias"))
	b.Write(make([]byte, 8)) // timestamp
	b.Write(u32b(0))         // chain length
	b.Write(bksCertRecord(leaf))

	// Entry 2: KEY (type 2) with a 1-cert chain + encrypted key blob (skipped).
	b.WriteByte(2)
	b.Write(utfb("key-alias"))
	b.Write(make([]byte, 8))
	b.Write(u32b(1)) // chain length 1
	b.Write(bksCertRecord(chain))
	b.WriteByte(0)         // keyType
	b.Write(utfb("PKCS8")) // keyFormat
	b.Write(utfb("RSA"))   // keyAlgorithm
	b.Write(bksData([]byte("encrypted-key-material")))

	// Entry 3: SEALED (type 4) — length-prefixed blob, must be skipped cleanly.
	b.WriteByte(4)
	b.Write(utfb("sealed-alias"))
	b.Write(make([]byte, 8))
	b.Write(u32b(0)) // chain length
	b.Write(bksData([]byte("sealed-object-bytes")))

	b.WriteByte(0)            // end sentinel
	b.Write(make([]byte, 20)) // trailing HMAC (ignored)

	certs, hasKey, opened := openBKS(b.Bytes())
	if !opened {
		t.Fatal("expected opened=true")
	}
	if !hasKey {
		t.Error("expected hasPrivateKey=true (key entry present)")
	}
	names := map[string]bool{}
	for _, c := range certs {
		names[c.Subject.CommonName] = true
	}
	if !names["bks-leaf.example.com"] || !names["bks-ca.example.com"] {
		t.Errorf("expected leaf + chain certs, got %d: %v", len(certs), names)
	}
}

func TestOpenBKS_BadVersionNotOpened(t *testing.T) {
	if _, _, opened := openBKS([]byte{0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 0}); opened {
		t.Error("bad version must not open")
	}
}

func TestOpenBKS_EmptyStore(t *testing.T) {
	var b bytes.Buffer
	b.Write(bksHeader(1))
	b.WriteByte(0) // immediate end sentinel
	b.Write(make([]byte, 20))
	certs, _, opened := openBKS(b.Bytes())
	if !opened || len(certs) != 0 {
		t.Fatalf("empty store: opened=%v certs=%d, want true/0", opened, len(certs))
	}
}

func TestOpenBKS_TruncatedNoPanic(t *testing.T) {
	// Header only, then a truncated entry — must not panic.
	b := append(bksHeader(2), 1, 0x00) // type=1, then cut off mid-alias
	certs, _, opened := openBKS(b)
	if !opened {
		t.Error("valid header -> opened")
	}
	if len(certs) != 0 {
		t.Errorf("no certs from truncated entry, got %d", len(certs))
	}
}

func TestScanFile_BKSRouting(t *testing.T) {
	der := makeDER(t, "routed-bks.example.com")
	var b bytes.Buffer
	b.Write(bksHeader(2))
	b.WriteByte(1)
	b.Write(utfb("c"))
	b.Write(make([]byte, 8))
	b.Write(u32b(0))
	b.Write(bksCertRecord(der))
	b.WriteByte(0)
	b.Write(make([]byte, 20))

	findings, err := New().ScanFile("store.bks", b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var sawCert bool
	for _, f := range findings {
		if f.AssetType == types.AssetCertificate && f.Properties.SubjectName != "" {
			sawCert = true
		}
	}
	if !sawCert {
		t.Error("expected a certificate finding enumerated from the BKS store")
	}
}
