package types

// Finding represents a single cryptographic asset detected during scanning.
type Finding struct {
	// ID is the unique finding identifier (e.g. "FIND-001").
	ID string `json:"id"`
	// AssetType classifies the cryptographic asset (algorithm, protocol, certificate, related-crypto-material).
	AssetType AssetType `json:"asset_type"`
	// Name is the human-readable name of the asset (e.g. "AES-256-CBC", "TLS 1.2", "RSA-2048").
	Name string `json:"name"`
	// Location pinpoints the file, line, and column where the asset was found.
	Location Location `json:"location"`
	// Severity indicates the risk level of the finding.
	Severity Severity `json:"severity"`
	// Confidence indicates how certain the scanner is about the finding.
	Confidence Confidence `json:"confidence"`
	// Properties holds crypto-specific metadata mapping to CycloneDX cryptoProperties.
	Properties CryptoProperties `json:"properties"`
	// Description is a human-readable explanation of what was found.
	Description string `json:"description"`
	// RuleID identifies which detection rule or pattern matched (e.g. "cbom-python-hashlib-md5").
	RuleID string `json:"rule_id"`
	// Category classifies the rule as inventory or security. Drives filtering
	// and baseline scope (only security findings can be baselined).
	Category Category `json:"category,omitempty"`
	// Maturity indicates the rule's lifecycle state (experimental, stable, deprecated).
	Maturity Maturity `json:"maturity,omitempty"`
	// NoiseRisk is an informational tag describing expected false-positive rate.
	NoiseRisk NoiseRisk `json:"noise_risk,omitempty"`
	// DefaultEnabled echoes the rule's default_enabled flag. True means the
	// rule ran because it's in the default set; false means it was opted in.
	DefaultEnabled bool `json:"default_enabled,omitempty"`
	// Pass indicates which scanner pass found this (1, 2, or 3).
	Pass int `json:"pass"`
	// Fingerprint is a stable identity hash for deduplication across scans (ADR-034).
	// Computed as SHA-256(rule_id + ":" + file_path + ":" + normalized_code_signature).
	Fingerprint string `json:"fingerprint,omitempty"`
	// NormalizedSignature is the whitespace/comment/literal-normalized code snippet
	// used to compute the fingerprint. Stored for debugging and drift detection.
	NormalizedSignature string `json:"normalizedSignature,omitempty"`
}
