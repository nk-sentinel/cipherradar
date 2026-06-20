package types

// CryptoProperties holds crypto-specific metadata for a finding.
// Only fields relevant to the Finding's AssetType are populated.
// This maps to the CycloneDX 1.7 cryptoProperties component.
type CryptoProperties struct {
	// Primitive is the cryptographic primitive type (e.g. "block-cipher", "hash", "mac", "signature", "kdf", "key-agree", "pke", "ae").
	Primitive string `json:"primitive,omitempty"`
	// AlgorithmFamily is the algorithm family name (e.g. "aes", "rsa", "sha", "ecdh").
	AlgorithmFamily string `json:"algorithm_family,omitempty"`
	// Mode is the algorithm mode of operation (e.g. "cbc", "gcm", "ecb").
	Mode string `json:"mode,omitempty"`
	// Padding is the padding scheme used (e.g. "pkcs7", "oaep", "pkcs1v15").
	Padding string `json:"padding,omitempty"`
	// KeySize is the key size in bits (e.g. 256, 2048).
	KeySize int `json:"key_size,omitempty"`
	// ClassicalSecurity is the classical security level in bits.
	ClassicalSecurity int `json:"classical_security,omitempty"`
	// NistQuantumLevel is the NIST quantum security level (1-5, 0 if not applicable).
	NistQuantumLevel int `json:"nist_quantum_level,omitempty"`
	// QuantumStatus indicates the quantum-computing resistance status.
	QuantumStatus QuantumStatus `json:"quantum_status,omitempty"`
	// CryptoFunctions lists the cryptographic operations observed (e.g. ["encrypt", "decrypt", "generate"]).
	CryptoFunctions []string `json:"crypto_functions,omitempty"`

	// AlgorithmPrimitive is the canonical token for this finding's algorithm
	// (e.g. "MD5", "AES-256-GCM", "TLS-1.2"). Populated by the OpenGrep parser
	// from rule metadata (cbom-primitive or resolved from cbom-primitive-from-metavar).
	// Empty when the rule doesn't specify and no fallback applied.
	AlgorithmPrimitive string `json:"algorithm_primitive,omitempty"`

	// Library is the name of the cryptographic library involved in this finding
	// (e.g. "cryptography", "bouncycastle"). Populated by the parser from the
	// rule's cbom-library metadata. Empty when not a library-import rule.
	Library string `json:"library,omitempty"`
	// LibraryGroup, LibraryVersion, and LibraryPurl are populated by the
	// dependency-enrichment pass (cli/internal/deps) when the coarse Library
	// hint resolves to a concrete package in a project manifest/lockfile.
	// LibraryGroup is the Maven groupId (empty for npm/pypi).
	LibraryGroup   string `json:"library_group,omitempty"`
	LibraryVersion string `json:"library_version,omitempty"`
	LibraryPurl    string `json:"library_purl,omitempty"`

	// ProtocolType is the protocol type (e.g. "tls", "ssh", "ipsec").
	ProtocolType string `json:"protocol_type,omitempty"`
	// ProtocolVersion is the protocol version string (e.g. "1.2", "1.3").
	ProtocolVersion string `json:"protocol_version,omitempty"`
	// CipherSuites lists the cipher suites associated with the protocol (e.g. ["TLS_AES_256_GCM_SHA384"]).
	CipherSuites []string `json:"cipher_suites,omitempty"`

	// SubjectName is the certificate subject distinguished name.
	SubjectName string `json:"subject_name,omitempty"`
	// IssuerName is the certificate issuer distinguished name.
	IssuerName string `json:"issuer_name,omitempty"`
	// NotValidBefore is the certificate validity start date in RFC 3339 format.
	NotValidBefore string `json:"not_valid_before,omitempty"`
	// NotValidAfter is the certificate validity end date in RFC 3339 format.
	NotValidAfter string `json:"not_valid_after,omitempty"`
	// SignatureAlgorithm is the algorithm used to sign the certificate.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	// CertificateFormat is the certificate encoding format (e.g. "X.509", "PEM").
	CertificateFormat string `json:"certificate_format,omitempty"`
	// SubjectPublicKeyAlgorithm is the certificate's public-key algorithm
	// (e.g. "RSA", "ECDSA", "Ed25519"). Used to emit a linked key component.
	SubjectPublicKeyAlgorithm string `json:"subject_public_key_algorithm,omitempty"`
	// SubjectPublicKeySize is the certificate's public-key size in bits.
	SubjectPublicKeySize int `json:"subject_public_key_size,omitempty"`
	// CertificateExtensions holds formatted X.509 extension summaries
	// (KeyUsage, ExtendedKeyUsage, BasicConstraints, SubjectAltName).
	CertificateExtensions []string `json:"certificate_extensions,omitempty"`

	// MaterialType is the type of cryptographic material (e.g. "private-key", "public-key", "shared-secret", "iv", "nonce", "seed", "salt", "password").
	MaterialType string `json:"material_type,omitempty"`
	// MaterialSize is the size of the cryptographic material in bits.
	MaterialSize int `json:"material_size,omitempty"`
	// State is the lifecycle state of the material (e.g. "active", "expired", "revoked").
	State string `json:"state,omitempty"`
}
