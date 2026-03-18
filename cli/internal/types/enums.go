package types

// AssetType classifies the kind of cryptographic asset detected.
type AssetType string

const (
	// AssetAlgorithm represents a cryptographic algorithm (e.g. AES, RSA, SHA-256).
	AssetAlgorithm AssetType = "algorithm"
	// AssetProtocol represents a cryptographic protocol (e.g. TLS, SSH).
	AssetProtocol AssetType = "protocol"
	// AssetCertificate represents a digital certificate (e.g. X.509).
	AssetCertificate AssetType = "certificate"
	// AssetRelatedCryptoMaterial represents related cryptographic material (e.g. keys, IVs).
	AssetRelatedCryptoMaterial AssetType = "related-crypto-material"
)

// Severity indicates the risk level of a finding.
type Severity string

const (
	// SeverityCritical indicates a critical risk finding.
	SeverityCritical Severity = "critical"
	// SeverityHigh indicates a high risk finding.
	SeverityHigh Severity = "high"
	// SeverityMedium indicates a medium risk finding.
	SeverityMedium Severity = "medium"
	// SeverityLow indicates a low risk finding.
	SeverityLow Severity = "low"
	// SeverityInfo indicates an informational finding with no direct risk.
	SeverityInfo Severity = "info"
)

// Confidence indicates how certain the scanner is about a finding.
type Confidence string

const (
	// ConfidenceHigh indicates the scanner is highly certain about the finding.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates moderate certainty about the finding.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates low certainty about the finding.
	ConfidenceLow Confidence = "low"
	// ConfidenceUnresolved indicates the finding could not be confirmed or denied.
	ConfidenceUnresolved Confidence = "unresolved"
)

// QuantumStatus indicates the quantum-computing resistance status of a cryptographic asset.
type QuantumStatus string

const (
	// QuantumVulnerable indicates the asset is vulnerable to quantum attacks.
	QuantumVulnerable QuantumStatus = "quantum-vulnerable"
	// QuantumSafe indicates the asset is resistant to known quantum attacks.
	QuantumSafe QuantumStatus = "quantum-safe"
	// QuantumUnknown indicates the quantum resistance status is not determined.
	QuantumUnknown QuantumStatus = "quantum-unknown"
	// Broken indicates the asset is already broken by classical attacks.
	Broken QuantumStatus = "broken"
)
