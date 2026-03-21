// Package binary provides a byte-pattern matcher that detects cryptographic
// constants (S-boxes, round constants, OIDs) in compiled binaries and archives.
package binary

// CryptoPattern describes a known cryptographic byte sequence that identifies
// the presence of a particular algorithm in compiled code.
type CryptoPattern struct {
	// Name is the human-readable pattern name (e.g. "AES S-box").
	Name string
	// Family is the algorithm family key used for quantum classification
	// (e.g. "aes", "sha-256", "rsa").
	Family string
	// Primitive is the CycloneDX crypto primitive type.
	Primitive string
	// Bytes is the reference byte sequence.
	Bytes []byte
	// MinMatch is the minimum number of consecutive matching bytes required
	// for a positive detection. This allows partial matches on truncated or
	// compiler-reordered tables.
	MinMatch int
}

// cryptoPatterns contains well-known byte signatures for cryptographic
// algorithms found in compiled binaries. Each pattern is derived from the
// algorithm specification (FIPS, RFC, etc.) and represents constant tables
// or magic values that survive compilation.
//
//nolint:lll // byte literal tables are inherently wide
var cryptoPatterns = []CryptoPattern{
	// -----------------------------------------------------------------------
	// AES (FIPS 197)
	// -----------------------------------------------------------------------
	{
		Name:      "AES S-box",
		Family:    "aes",
		Primitive: "block-cipher",
		Bytes: []byte{
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
			0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
			0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
			0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
			0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		},
		MinMatch: 32,
	},
	{
		Name:      "AES Inverse S-box",
		Family:    "aes",
		Primitive: "block-cipher",
		Bytes: []byte{
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
			0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
			0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
			0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
			0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		},
		MinMatch: 32,
	},

	// -----------------------------------------------------------------------
	// SHA-256 (FIPS 180-4) — first 16 round constants K[0..15], big-endian
	// -----------------------------------------------------------------------
	{
		Name:      "SHA-256 Round Constants",
		Family:    "sha-256",
		Primitive: "hash",
		Bytes: []byte{
			0x42, 0x8a, 0x2f, 0x98, // K[0]
			0x71, 0x37, 0x44, 0x91, // K[1]
			0xb5, 0xc0, 0xfb, 0xcf, // K[2]
			0xe9, 0xb5, 0xdb, 0xa5, // K[3]
			0x39, 0x56, 0xc2, 0x5b, // K[4]
			0x59, 0xf1, 0x11, 0xf1, // K[5]
			0x92, 0x3f, 0x82, 0xa4, // K[6]
			0xab, 0x1c, 0x5e, 0xd5, // K[7]
			0xd8, 0x07, 0xaa, 0x98, // K[8]
			0x12, 0x83, 0x5b, 0x01, // K[9]
			0x24, 0x31, 0x85, 0xbe, // K[10]
			0x55, 0x0c, 0x7d, 0xc3, // K[11]
			0x72, 0xbe, 0x5d, 0x74, // K[12]
			0x80, 0xde, 0xb1, 0xfe, // K[13]
			0x9b, 0xdc, 0x06, 0xa7, // K[14]
			0xc1, 0x9b, 0xf1, 0x74, // K[15]
		},
		MinMatch: 16,
	},
	// SHA-256 round constants, little-endian (x86/ARM LE binaries)
	{
		Name:      "SHA-256 Round Constants (LE)",
		Family:    "sha-256",
		Primitive: "hash",
		Bytes: []byte{
			0x98, 0x2f, 0x8a, 0x42, // K[0] LE
			0x91, 0x44, 0x37, 0x71, // K[1] LE
			0xcf, 0xfb, 0xc0, 0xb5, // K[2] LE
			0xa5, 0xdb, 0xb5, 0xe9, // K[3] LE
			0x5b, 0xc2, 0x56, 0x39, // K[4] LE
			0xf1, 0x11, 0xf1, 0x59, // K[5] LE
			0xa4, 0x82, 0x3f, 0x92, // K[6] LE
			0xd5, 0x5e, 0x1c, 0xab, // K[7] LE
		},
		MinMatch: 16,
	},

	// -----------------------------------------------------------------------
	// SHA-1 (FIPS 180-4) — initial hash values H0..H4, big-endian
	// -----------------------------------------------------------------------
	{
		Name:      "SHA-1 Init Vector",
		Family:    "sha1",
		Primitive: "hash",
		Bytes: []byte{
			0x67, 0x45, 0x23, 0x01, // H0
			0xEF, 0xCD, 0xAB, 0x89, // H1
			0x98, 0xBA, 0xDC, 0xFE, // H2
			0x10, 0x32, 0x54, 0x76, // H3
			0xC3, 0xD2, 0xE1, 0xF0, // H4
		},
		MinMatch: 20,
	},

	// -----------------------------------------------------------------------
	// MD5 (RFC 1321) — T-table first 16 entries, little-endian
	// -----------------------------------------------------------------------
	{
		Name:      "MD5 T-table",
		Family:    "md5",
		Primitive: "hash",
		Bytes: []byte{
			0x78, 0xa4, 0x6a, 0xd7, // T[1]
			0x56, 0xb7, 0xc7, 0xe8, // T[2]
			0xdb, 0x70, 0x20, 0x24, // T[3]
			0xee, 0xce, 0xbd, 0xc1, // T[4]
			0xaf, 0x0f, 0x7c, 0xf5, // T[5]
			0x2a, 0xc6, 0x87, 0x47, // T[6]
			0x13, 0x46, 0x30, 0xa8, // T[7]
			0x01, 0x95, 0x46, 0xfd, // T[8]
		},
		MinMatch: 16,
	},

	// -----------------------------------------------------------------------
	// DES (FIPS 46-3) — Initial Permutation table (first 32 entries)
	// -----------------------------------------------------------------------
	{
		Name:      "DES Initial Permutation",
		Family:    "des",
		Primitive: "block-cipher",
		Bytes: []byte{
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
		},
		MinMatch: 16,
	},
	// DES S-box 1 (6-bit input to 4-bit output, 64 entries)
	{
		Name:      "DES S-box 1",
		Family:    "des",
		Primitive: "block-cipher",
		Bytes: []byte{
			14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
		},
		MinMatch: 32,
	},

	// -----------------------------------------------------------------------
	// Blowfish — P-array first 18 uint32 values (big-endian)
	// -----------------------------------------------------------------------
	{
		Name:      "Blowfish P-array",
		Family:    "blowfish",
		Primitive: "block-cipher",
		Bytes: []byte{
			0x24, 0x3f, 0x6a, 0x88, // P[0]
			0x85, 0xa3, 0x08, 0xd3, // P[1]
			0x13, 0x19, 0x8a, 0x2e, // P[2]
			0x03, 0x70, 0x73, 0x44, // P[3]
			0xa4, 0x09, 0x38, 0x22, // P[4]
			0x29, 0x9f, 0x31, 0xd0, // P[5]
			0x08, 0x2e, 0xfa, 0x98, // P[6]
			0xec, 0x4e, 0x6c, 0x89, // P[7]
		},
		MinMatch: 16,
	},

	// -----------------------------------------------------------------------
	// Algorithm OIDs (ASN.1 DER encoded)
	// -----------------------------------------------------------------------
	{
		Name:      "RSA OID (1.2.840.113549.1.1)",
		Family:    "rsa",
		Primitive: "pke",
		// OID 1.2.840.113549.1.1 = 06 09 2a 86 48 86 f7 0d 01 01 (with tag+len)
		Bytes:    []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01},
		MinMatch: 8,
	},
	{
		Name:      "ECDSA OID (1.2.840.10045.4.3)",
		Family:    "ecdsa",
		Primitive: "signature",
		// OID 1.2.840.10045.4.3
		Bytes:    []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03},
		MinMatch: 7,
	},
	{
		Name:      "Ed25519 OID (1.3.101.112)",
		Family:    "ed25519",
		Primitive: "signature",
		// OID 1.3.101.112
		Bytes:    []byte{0x2b, 0x65, 0x70},
		MinMatch: 3,
	},
	{
		Name:      "AES-CBC OID (2.16.840.1.101.3.4.1.2)",
		Family:    "aes",
		Primitive: "block-cipher",
		// OID 2.16.840.1.101.3.4.1.2
		Bytes:    []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02},
		MinMatch: 9,
	},
	{
		Name:      "AES-GCM OID (2.16.840.1.101.3.4.1.6)",
		Family:    "aes",
		Primitive: "ae",
		// OID 2.16.840.1.101.3.4.1.6
		Bytes:    []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06},
		MinMatch: 9,
	},
	{
		Name:      "SHA-256 OID (2.16.840.1.101.3.4.2.1)",
		Family:    "sha-256",
		Primitive: "hash",
		// OID 2.16.840.1.101.3.4.2.1
		Bytes:    []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01},
		MinMatch: 9,
	},
	{
		Name:      "SHA-512 OID (2.16.840.1.101.3.4.2.3)",
		Family:    "sha-512",
		Primitive: "hash",
		// OID 2.16.840.1.101.3.4.2.3
		Bytes:    []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03},
		MinMatch: 9,
	},
	{
		Name:      "MD5 OID (1.2.840.113549.2.5)",
		Family:    "md5",
		Primitive: "hash",
		// OID 1.2.840.113549.2.5
		Bytes:    []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05},
		MinMatch: 8,
	},

	// -----------------------------------------------------------------------
	// RC4 — the identity permutation header (state init S[0..15])
	// -----------------------------------------------------------------------
	{
		Name:      "RC4 State Init",
		Family:    "rc4",
		Primitive: "stream-cipher",
		Bytes: []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		MinMatch: 32,
	},
}
