package cyclonedx17

// CertificateProperties represents the certificate-specific properties
// of a cryptographic asset as defined in CycloneDX 1.7.
type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty" xml:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty" xml:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty" xml:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty" xml:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty" xml:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty" xml:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty" xml:"certificateFormat,omitempty"`
	CertificateExtension  string `json:"certificateExtension,omitempty" xml:"certificateExtension,omitempty"`
}
