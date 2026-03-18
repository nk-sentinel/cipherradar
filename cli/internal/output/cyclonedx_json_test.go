package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

func newTestScanResult() *types.ScanResult {
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	return &types.ScanResult{
		Target:       "/tmp/test-project",
		StartTime:    now,
		EndTime:      now.Add(2 * time.Second),
		PassesRun:    []int{1},
		FilesScanned: 5,
		Findings: []types.Finding{
			{
				ID:        "FIND-001",
				AssetType: types.AssetAlgorithm,
				Name:      "AES-256-CBC",
				Location: types.Location{
					File:      "crypto.py",
					StartLine: 7,
					StartCol:  5,
				},
				Severity:   types.SeverityMedium,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					Primitive:       "block-cipher",
					AlgorithmFamily: "aes",
					Mode:            "cbc",
					KeySize:         256,
					QuantumStatus:   types.QuantumVulnerable,
					CryptoFunctions: []string{"encrypt"},
				},
				Description: "AES-256 in CBC mode",
				RuleID:      "cbom-python-cipher-aes",
				Pass:        1,
			},
			{
				ID:        "FIND-002",
				AssetType: types.AssetProtocol,
				Name:      "TLS 1.2",
				Location: types.Location{
					File:      "ssl_usage.py",
					StartLine: 4,
					StartCol:  10,
				},
				Severity:   types.SeverityLow,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					ProtocolType:    "tls",
					ProtocolVersion: "1.2",
					CipherSuites:   []string{"TLS_AES_256_GCM_SHA384"},
					QuantumStatus:   types.QuantumVulnerable,
				},
				Description: "TLS 1.2 protocol usage",
				RuleID:      "cbom-python-ssl-context",
				Pass:        1,
			},
			{
				ID:        "FIND-003",
				AssetType: types.AssetCertificate,
				Name:      "X.509 Certificate",
				Location: types.Location{
					File:      "certs.py",
					StartLine: 15,
					StartCol:  1,
				},
				Severity:   types.SeverityInfo,
				Confidence: types.ConfidenceMedium,
				Properties: types.CryptoProperties{
					SubjectName:       "CN=example.com",
					IssuerName:        "CN=CA",
					NotValidBefore:    "2025-01-01T00:00:00Z",
					NotValidAfter:     "2026-01-01T00:00:00Z",
					CertificateFormat: "X.509",
					QuantumStatus:     types.QuantumUnknown,
				},
				Description: "X.509 certificate",
				RuleID:      "cbom-python-cert",
				Pass:        1,
			},
			{
				ID:        "FIND-004",
				AssetType: types.AssetRelatedCryptoMaterial,
				Name:      "RSA Private Key",
				Location: types.Location{
					File:      "keys.py",
					StartLine: 22,
					StartCol:  3,
				},
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Properties: types.CryptoProperties{
					MaterialType: "private-key",
					MaterialSize: 2048,
					State:        "active",
					QuantumStatus: types.QuantumVulnerable,
				},
				Description: "RSA private key generation",
				RuleID:      "cbom-python-rsa-keygen",
				Pass:        1,
			},
		},
	}
}

func TestConvertScanResult_BOMEnvelope(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("SpecVersion = %q, want %q", bom.SpecVersion, "1.7")
	}
	if bom.Version != 1 {
		t.Errorf("Version = %d, want 1", bom.Version)
	}
	if bom.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
}

func TestConvertScanResult_Metadata(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	if bom.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}
	if bom.Metadata.Timestamp != "2026-03-18T12:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", bom.Metadata.Timestamp, "2026-03-18T12:00:00Z")
	}
	if len(bom.Metadata.Tools) != 1 {
		t.Fatalf("len(Tools) = %d, want 1", len(bom.Metadata.Tools))
	}
	if bom.Metadata.Tools[0].Name != "CipherRadar" {
		t.Errorf("Tool.Name = %q, want %q", bom.Metadata.Tools[0].Name, "CipherRadar")
	}
	if bom.Metadata.Tools[0].Version == "" {
		t.Error("Tool.Version should not be empty")
	}
}

func TestConvertScanResult_ComponentCount(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	if len(bom.Components) != 4 {
		t.Errorf("len(Components) = %d, want 4", len(bom.Components))
	}
}

func TestConvertScanResult_ComponentType(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	for _, c := range bom.Components {
		if c.Type != "cryptographic-asset" {
			t.Errorf("Component %q Type = %q, want %q", c.Name, c.Type, "cryptographic-asset")
		}
	}
}

func TestConvertScanResult_AlgorithmAssetType(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	comp := findComponent(bom, "FIND-001")
	if comp == nil {
		t.Fatal("component FIND-001 not found")
	}

	cp := comp.CryptoProperties
	if cp == nil {
		t.Fatal("cryptoProperties should not be nil")
	}
	if cp.AssetType != "algorithm" {
		t.Errorf("assetType = %q, want %q", cp.AssetType, "algorithm")
	}
	if cp.AlgorithmProperties == nil {
		t.Fatal("algorithmProperties should not be nil")
	}
	if cp.AlgorithmProperties.Primitive != "block-cipher" {
		t.Errorf("primitive = %q, want %q", cp.AlgorithmProperties.Primitive, "block-cipher")
	}
	if cp.AlgorithmProperties.AlgorithmFamily != "AES" {
		t.Errorf("algorithmFamily = %q, want %q", cp.AlgorithmProperties.AlgorithmFamily, "AES")
	}
	if cp.AlgorithmProperties.Mode != "cbc" {
		t.Errorf("mode = %q, want %q", cp.AlgorithmProperties.Mode, "cbc")
	}
	if cp.AlgorithmProperties.ClassicalSecurityLevel != 256 {
		t.Errorf("classicalSecurityLevel = %d, want 256", cp.AlgorithmProperties.ClassicalSecurityLevel)
	}
	if len(cp.AlgorithmProperties.CryptoFunctions) != 1 {
		t.Fatalf("len(cryptoFunctions) = %d, want 1", len(cp.AlgorithmProperties.CryptoFunctions))
	}
	if cp.AlgorithmProperties.CryptoFunctions[0] != "encrypt" {
		t.Errorf("cryptoFunctions[0] = %q, want %q", cp.AlgorithmProperties.CryptoFunctions[0], "encrypt")
	}
}

func TestConvertScanResult_ProtocolAssetType(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	comp := findComponent(bom, "FIND-002")
	if comp == nil {
		t.Fatal("component FIND-002 not found")
	}

	cp := comp.CryptoProperties
	if cp == nil {
		t.Fatal("cryptoProperties should not be nil")
	}
	if cp.AssetType != "protocol" {
		t.Errorf("assetType = %q, want %q", cp.AssetType, "protocol")
	}
	if cp.ProtocolProperties == nil {
		t.Fatal("protocolProperties should not be nil")
	}
	if cp.ProtocolProperties.Type != "tls" {
		t.Errorf("type = %q, want %q", cp.ProtocolProperties.Type, "tls")
	}
	if cp.ProtocolProperties.Version != "1.2" {
		t.Errorf("version = %q, want %q", cp.ProtocolProperties.Version, "1.2")
	}
	if len(cp.ProtocolProperties.CipherSuites) != 1 {
		t.Fatalf("len(cipherSuites) = %d, want 1", len(cp.ProtocolProperties.CipherSuites))
	}
	if cp.ProtocolProperties.CipherSuites[0].Name != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("cipherSuite name = %q, want %q", cp.ProtocolProperties.CipherSuites[0].Name, "TLS_AES_256_GCM_SHA384")
	}
}

func TestConvertScanResult_CertificateAssetType(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	comp := findComponent(bom, "FIND-003")
	if comp == nil {
		t.Fatal("component FIND-003 not found")
	}

	cp := comp.CryptoProperties
	if cp == nil {
		t.Fatal("cryptoProperties should not be nil")
	}
	if cp.AssetType != "certificate" {
		t.Errorf("assetType = %q, want %q", cp.AssetType, "certificate")
	}
	if cp.CertificateProperties == nil {
		t.Fatal("certificateProperties should not be nil")
	}
	if cp.CertificateProperties.SubjectName != "CN=example.com" {
		t.Errorf("subjectName = %q, want %q", cp.CertificateProperties.SubjectName, "CN=example.com")
	}
	if cp.CertificateProperties.CertificateFormat != "X.509" {
		t.Errorf("certificateFormat = %q, want %q", cp.CertificateProperties.CertificateFormat, "X.509")
	}
}

func TestConvertScanResult_RelatedCryptoMaterialAssetType(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	comp := findComponent(bom, "FIND-004")
	if comp == nil {
		t.Fatal("component FIND-004 not found")
	}

	cp := comp.CryptoProperties
	if cp == nil {
		t.Fatal("cryptoProperties should not be nil")
	}
	if cp.AssetType != "related-crypto-material" {
		t.Errorf("assetType = %q, want %q", cp.AssetType, "related-crypto-material")
	}
	if cp.RelatedCryptoMaterialProperties == nil {
		t.Fatal("relatedCryptoMaterialProperties should not be nil")
	}
	if cp.RelatedCryptoMaterialProperties.Type != "private-key" {
		t.Errorf("type = %q, want %q", cp.RelatedCryptoMaterialProperties.Type, "private-key")
	}
	if cp.RelatedCryptoMaterialProperties.Size != 2048 {
		t.Errorf("size = %d, want 2048", cp.RelatedCryptoMaterialProperties.Size)
	}
	if cp.RelatedCryptoMaterialProperties.State != "active" {
		t.Errorf("state = %q, want %q", cp.RelatedCryptoMaterialProperties.State, "active")
	}
}

func TestConvertScanResult_Evidence(t *testing.T) {
	result := newTestScanResult()
	bom := ConvertScanResult(result)

	comp := findComponent(bom, "FIND-001")
	if comp == nil {
		t.Fatal("component FIND-001 not found")
	}
	if comp.Evidence == nil {
		t.Fatal("evidence should not be nil")
	}
	if len(comp.Evidence.Occurrences) != 1 {
		t.Fatalf("len(occurrences) = %d, want 1", len(comp.Evidence.Occurrences))
	}
	occ := comp.Evidence.Occurrences[0]
	if occ.Location != "crypto.py" {
		t.Errorf("location = %q, want %q", occ.Location, "crypto.py")
	}
	if occ.Line != 7 {
		t.Errorf("line = %d, want 7", occ.Line)
	}
}

func TestCycloneDXJSONWriter_ProducesValidJSON(t *testing.T) {
	result := newTestScanResult()
	w := &CycloneDXJSONWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestCycloneDXJSONWriter_BOMFormatAndSpecVersion(t *testing.T) {
	result := newTestScanResult()
	w := &CycloneDXJSONWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want %q", raw["bomFormat"], "CycloneDX")
	}
	if raw["specVersion"] != "1.7" {
		t.Errorf("specVersion = %v, want %q", raw["specVersion"], "1.7")
	}
}

func TestCycloneDXJSONWriter_ComponentsHaveCryptoProperties(t *testing.T) {
	result := newTestScanResult()
	w := &CycloneDXJSONWriter{}

	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	components, ok := raw["components"].([]interface{})
	if !ok {
		t.Fatal("components should be an array")
	}

	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			t.Fatal("component should be an object")
		}
		if _, hasCrypto := comp["cryptoProperties"]; !hasCrypto {
			t.Errorf("component %v missing cryptoProperties", comp["name"])
		}
	}
}

func TestCycloneDXJSONWriter_EmptyFindings(t *testing.T) {
	result := &types.ScanResult{
		Target:       "/tmp/empty",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		PassesRun:    []int{1},
		FilesScanned: 0,
	}

	w := &CycloneDXJSONWriter{}
	var buf bytes.Buffer
	err := w.WriteScanResult(&buf, result)
	if err != nil {
		t.Fatalf("WriteScanResult returned error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if raw["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want %q", raw["bomFormat"], "CycloneDX")
	}
}

// findComponent finds a component by bom-ref.
func findComponent(bom *BOM, bomRef string) *Component {
	for i := range bom.Components {
		if bom.Components[i].BOMRef == bomRef {
			return &bom.Components[i]
		}
	}
	return nil
}
