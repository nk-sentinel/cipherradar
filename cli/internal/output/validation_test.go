package output

import (
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/cyclonedx17"
)

func TestPrimitiveClosedSet(t *testing.T) {
	want := []cyclonedx17.Primitive{
		cyclonedx17.PrimitiveDRBG, cyclonedx17.PrimitiveMAC, cyclonedx17.PrimitiveBlockCipher,
		cyclonedx17.PrimitiveStreamCipher, cyclonedx17.PrimitiveSignature, cyclonedx17.PrimitiveHash,
		cyclonedx17.PrimitivePKE, cyclonedx17.PrimitiveXOF, cyclonedx17.PrimitiveKDF,
		cyclonedx17.PrimitiveKeyAgree, cyclonedx17.PrimitiveKEM, cyclonedx17.PrimitiveAE,
		cyclonedx17.PrimitiveCombiner, cyclonedx17.PrimitiveKeyWrap,
		cyclonedx17.PrimitiveOther, cyclonedx17.PrimitiveUnknown,
	}
	for _, v := range want {
		if !validPrimitives[v] {
			t.Errorf("validPrimitives missing %q", v)
		}
	}
}

func TestAssetTypeClosedSet(t *testing.T) {
	want := []string{"algorithm", "certificate", "protocol", "related-crypto-material"}
	for _, v := range want {
		if !validAssetTypes[v] {
			t.Errorf("validAssetTypes missing %q", v)
		}
	}
	// Bug-B canary — library MUST NOT be in the set.
	if validAssetTypes["library"] {
		t.Error("validAssetTypes should NOT contain library; that's the bug we're fixing")
	}
}

func TestValidationTally_AllRecordersIncrementCorrectField(t *testing.T) {
	var v validationTally
	for _, tc := range []struct {
		name   string
		record func(*validationTally, string)
		field  func(*validationTally) int
	}{
		{"primitive", (*validationTally).recordPrimitive, func(v *validationTally) int { return v.Primitives }},
		{"assetType", (*validationTally).recordAssetType, func(v *validationTally) int { return v.AssetTypes }},
		{"algorithmFamily", (*validationTally).recordAlgorithmFamily, func(v *validationTally) int { return v.AlgorithmFamilies }},
		{"mode", (*validationTally).recordMode, func(v *validationTally) int { return v.Modes }},
		{"padding", (*validationTally).recordPadding, func(v *validationTally) int { return v.Paddings }},
		{"cryptoFunction", (*validationTally).recordCryptoFunction, func(v *validationTally) int { return v.CryptoFunctions }},
		{"materialType", (*validationTally).recordMaterialType, func(v *validationTally) int { return v.RelatedMaterialTypes }},
	} {
		before := tc.field(&v)
		tc.record(&v, "test-value")
		after := tc.field(&v)
		if after-before != 1 {
			t.Errorf("%s: expected field to increment by 1, got delta %d", tc.name, after-before)
		}
	}
	if v.Total != 7 {
		t.Errorf("Total = %d, want 7", v.Total)
	}
}

func TestAlgorithmFamilyClosedSet(t *testing.T) {
	// Spot-check that AES and ML-KEM are present.
	if !validAlgorithmFamilies[cyclonedx17.AlgorithmFamilyAES] {
		t.Error("validAlgorithmFamilies missing AES")
	}
	if !validAlgorithmFamilies[cyclonedx17.AlgorithmFamilyMLKEM] {
		t.Error("validAlgorithmFamilies missing ML-KEM")
	}
	// Expect ~95 entries; pin a sane minimum so we'd notice if many constants disappeared.
	if len(validAlgorithmFamilies) < 90 {
		t.Errorf("validAlgorithmFamilies has %d entries, want >= 90", len(validAlgorithmFamilies))
	}
}

func TestValidationTally_RecordAndSummary(t *testing.T) {
	var v validationTally
	v.recordPrimitive("HARDCODED-SECRET")
	v.recordAssetType("library")
	v.recordAssetType("library") // dedupe-by-value not required, but Total counts both
	if v.Total != 3 {
		t.Errorf("Total = %d, want 3", v.Total)
	}
	if v.Primitives != 1 {
		t.Errorf("Primitives = %d, want 1", v.Primitives)
	}
	if v.AssetTypes != 2 {
		t.Errorf("AssetTypes = %d, want 2", v.AssetTypes)
	}
	s := v.Summary()
	if !strings.Contains(s, "3 normalization violation") {
		t.Errorf("Summary = %q, want it to mention 3 violations", s)
	}
}
