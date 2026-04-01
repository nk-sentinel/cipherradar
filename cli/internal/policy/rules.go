package policy

// PolicyConfig represents a parsed policy.cradar.yml file.
type PolicyConfig struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Rule represents a single policy rule.
type Rule struct {
	ID          string    `yaml:"id" json:"id"`
	Description string    `yaml:"description" json:"description"`
	Severity    string    `yaml:"severity" json:"severity"` // severity assigned to violations
	Action      string    `yaml:"action" json:"action"`     // "fail" or "warn"
	Condition   Condition `yaml:"condition" json:"condition"`
}

// Condition defines what the rule checks.
type Condition struct {
	// Algorithm-based rules
	DenyAlgorithms []string `yaml:"deny_algorithms,omitempty" json:"deny_algorithms,omitempty"` // e.g. ["md5", "sha1", "des", "3des", "rc4"]
	DenyModes      []string `yaml:"deny_modes,omitempty" json:"deny_modes,omitempty"`           // e.g. ["ecb"]

	// Key size rules
	MinKeySize int    `yaml:"min_key_size,omitempty" json:"min_key_size,omitempty"` // e.g. 2048 for RSA
	Algorithm  string `yaml:"algorithm,omitempty" json:"algorithm,omitempty"`       // which algorithm the key size applies to

	// TLS version rules
	DenyTLSVersions []string `yaml:"deny_tls_versions,omitempty" json:"deny_tls_versions,omitempty"` // e.g. ["1.0", "1.1"]

	// Quantum status rules
	DenyQuantumStatus []string `yaml:"deny_quantum_status,omitempty" json:"deny_quantum_status,omitempty"` // e.g. ["quantum-vulnerable", "broken"]

	// Severity threshold — flag any finding at or above this severity
	MinSeverity string `yaml:"min_severity,omitempty" json:"min_severity,omitempty"` // e.g. "high"
}
