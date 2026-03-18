package cyclonedx17

// AlgorithmProperties represents the algorithm-specific properties
// of a cryptographic asset as defined in CycloneDX 1.7.
type AlgorithmProperties struct {
	Primitive                Primitive        `json:"primitive,omitempty" xml:"primitive,omitempty"`
	AlgorithmFamily          AlgorithmFamily  `json:"algorithmFamily,omitempty" xml:"algorithmFamily,omitempty"`
	ParameterSetIdentifier   string           `json:"parameterSetIdentifier,omitempty" xml:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment     string           `json:"executionEnvironment,omitempty" xml:"executionEnvironment,omitempty"`
	ImplementationPlatform   string           `json:"implementationPlatform,omitempty" xml:"implementationPlatform,omitempty"`
	CertificationLevels      []string         `json:"certificationLevel,omitempty" xml:"certificationLevel,omitempty"`
	Mode                     Mode             `json:"mode,omitempty" xml:"mode,omitempty"`
	Padding                  Padding          `json:"padding,omitempty" xml:"padding,omitempty"`
	CryptoFunctions          []CryptoFunction `json:"cryptoFunctions,omitempty" xml:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int              `json:"classicalSecurityLevel,omitempty" xml:"classicalSecurityLevel,omitempty"`
	NistQuantumSecurityLevel int              `json:"nistQuantumSecurityLevel,omitempty" xml:"nistQuantumSecurityLevel,omitempty"`
}
