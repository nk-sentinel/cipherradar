package cyclonedx17

// CryptoProperties is the top-level struct for CycloneDX 1.7 cryptoProperties.
// Exactly one of the four property types should be set, based on the asset type.
type CryptoProperties struct {
	AssetType                       string                           `json:"assetType" xml:"assetType"`
	AlgorithmProperties             *AlgorithmProperties             `json:"algorithmProperties,omitempty" xml:"algorithmProperties,omitempty"`
	CertificateProperties           *CertificateProperties           `json:"certificateProperties,omitempty" xml:"certificateProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties              `json:"protocolProperties,omitempty" xml:"protocolProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty" xml:"relatedCryptoMaterialProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty" xml:"oid,omitempty"`
}
