package cyclonedx17

// ProtocolProperties represents the protocol-specific properties
// of a cryptographic asset as defined in CycloneDX 1.7.
type ProtocolProperties struct {
	Type                string           `json:"type,omitempty" xml:"type,omitempty"`
	Version             string           `json:"version,omitempty" xml:"version,omitempty"`
	CipherSuites        []CipherSuite    `json:"cipherSuites,omitempty" xml:"cipherSuites,omitempty"`
	IKEv2TransformTypes []IKEv2Transform `json:"ikev2TransformTypes,omitempty" xml:"ikev2TransformTypes,omitempty"`
	CryptoRefArray      []string         `json:"cryptoRefArray,omitempty" xml:"cryptoRefArray,omitempty"`
}

// CipherSuite represents a cipher suite within a protocol as defined in CycloneDX 1.7.
type CipherSuite struct {
	Name        string   `json:"name,omitempty" xml:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty" xml:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty" xml:"identifiers,omitempty"`
}

// IKEv2Transform represents an IKEv2 transform type as defined in CycloneDX 1.7.
type IKEv2Transform struct {
	Type       string   `json:"type,omitempty" xml:"type,omitempty"`
	Algorithms []string `json:"algorithms,omitempty" xml:"algorithms,omitempty"`
}
