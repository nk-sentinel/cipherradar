package cyclonedx17

// RelatedCryptoMaterialProperties represents the properties of related
// cryptographic material as defined in CycloneDX 1.7.
type RelatedCryptoMaterialProperties struct {
	Type         RelatedCryptoMaterialType  `json:"type,omitempty" xml:"type,omitempty"`
	ID           string                     `json:"id,omitempty" xml:"id,omitempty"`
	State        RelatedCryptoMaterialState `json:"state,omitempty" xml:"state,omitempty"`
	AlgorithmRef string                     `json:"algorithmRef,omitempty" xml:"algorithmRef,omitempty"`
	SecuredBy    *SecuredBy                 `json:"securedBy,omitempty" xml:"securedBy,omitempty"`
	Size         int                        `json:"size,omitempty" xml:"size,omitempty"`
}

// SecuredBy describes how a piece of cryptographic material is secured.
type SecuredBy struct {
	Mechanism    string `json:"mechanism,omitempty" xml:"mechanism,omitempty"`
	AlgorithmRef string `json:"algorithmRef,omitempty" xml:"algorithmRef,omitempty"`
}
