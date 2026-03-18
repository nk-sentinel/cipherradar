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
	// Pass indicates which scanner pass found this (1, 2, or 3).
	Pass int `json:"pass"`
}
