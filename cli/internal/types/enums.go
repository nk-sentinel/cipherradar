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

// Category classifies a detection rule as either inventory (asset enumeration)
// or security (risk identification). Drives the --only-inventory / --only-security
// filters and scopes baseline suppression to security findings only.
type Category string

const (
	// CategoryInventory marks a rule that enumerates crypto assets without
	// implying a security concern (e.g. "RSA-2048 is used here").
	CategoryInventory Category = "inventory"
	// CategorySecurity marks a rule that flags a potential security issue
	// (e.g. weak cipher, hardcoded key, deprecated protocol).
	CategorySecurity Category = "security"
)

// Maturity indicates a rule's readiness for default execution. Combined with
// default_enabled, it gates whether a rule runs on an unflagged scan.
type Maturity string

const (
	// MaturityExperimental indicates a rule under evaluation; requires
	// --include-experimental (unless default_enabled: true is set explicitly).
	MaturityExperimental Maturity = "experimental"
	// MaturityStable indicates a rule validated for production use.
	MaturityStable Maturity = "stable"
	// MaturityDeprecated indicates a rule slated for removal; runs with a
	// stderr warning for 2 minor releases per ADR-034.
	MaturityDeprecated Maturity = "deprecated"
)

// NoiseRisk is an informational tag describing expected false-positive rate.
// It does not gate execution; rule authors setting NoiseRiskHigh should also
// set default_enabled: false so noisy rules stay opt-in.
type NoiseRisk string

const (
	// NoiseRiskLow indicates the rule is mechanical and rarely false-positives.
	NoiseRiskLow NoiseRisk = "low"
	// NoiseRiskMedium indicates occasional false positives.
	NoiseRiskMedium NoiseRisk = "med"
	// NoiseRiskHigh indicates frequent false positives; enable with care.
	NoiseRiskHigh NoiseRisk = "high"
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
