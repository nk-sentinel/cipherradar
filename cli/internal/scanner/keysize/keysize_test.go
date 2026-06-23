package keysize

import (
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func TestInferFromToken(t *testing.T) {
	cases := []struct {
		token string
		want  int
	}{
		{"AES-256-GCM", 256},
		{"AES-128-CBC", 128},
		{"RSA-2048", 2048},
		{"aes-256-gcm", 256},
		{"CAMELLIA-256-CBC", 256},
		{"SHA-256", 0},
		{"SHA256", 0},
		{"HMAC-SHA256", 0},
		{"MD5", 0},
		{"TLS-1.2", 0},
		{"P256-Signing", 256},
		{"", 0},
	}
	for _, tc := range cases {
		got := InferFromToken(tc.token)
		if got != tc.want {
			t.Errorf("InferFromToken(%q) = %d, want %d", tc.token, got, tc.want)
		}
	}
}

func TestCurveBits(t *testing.T) {
	if got := CurveBits("secp256r1"); got != 256 {
		t.Errorf("CurveBits(secp256r1) = %d, want 256", got)
	}
	if got := CurveBits("P-384"); got != 384 {
		t.Errorf("CurveBits(P-384) = %d, want 384", got)
	}
}

func TestEnrich(t *testing.T) {
	findings := []types.Finding{
		{
			AssetType: types.AssetAlgorithm,
			Name:      "AES-256-CBC",
			Properties: types.CryptoProperties{
				AlgorithmFamily: "aes",
				Primitive:       "block-cipher",
			},
		},
		{
			AssetType: types.AssetAlgorithm,
			Name:      "SHA-256",
			Properties: types.CryptoProperties{
				AlgorithmFamily: "sha-256",
				Primitive:       "hash",
			},
		},
		{
			AssetType: types.AssetAlgorithm,
			Name:      "RSA",
			Properties: types.CryptoProperties{
				AlgorithmFamily: "rsa",
				KeySize:         2048,
			},
		},
	}
	Enrich(findings)
	if findings[0].Properties.KeySize != 256 {
		t.Errorf("AES KeySize = %d, want 256", findings[0].Properties.KeySize)
	}
	if findings[1].Properties.KeySize != 0 {
		t.Errorf("SHA-256 KeySize = %d, want 0", findings[1].Properties.KeySize)
	}
	if findings[2].Properties.KeySize != 2048 {
		t.Errorf("RSA KeySize = %d, want 2048", findings[2].Properties.KeySize)
	}
}

func TestParsePHPPrivateKeyBits(t *testing.T) {
	cfg := `['private_key_bits' => 4096, 'private_key_type' => OPENSSL_KEYTYPE_RSA]`
	if got := ParsePHPPrivateKeyBits(cfg); got != 4096 {
		t.Errorf("ParsePHPPrivateKeyBits = %d, want 4096", got)
	}
}
