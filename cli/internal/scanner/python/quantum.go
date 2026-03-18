package python

import (
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// QuantumInfo holds the quantum readiness classification for a crypto algorithm.
type QuantumInfo struct {
	Status         types.QuantumStatus
	NistLevel      int    // 0 if not applicable
	Recommendation string // migration guidance
}

// quantumTable maps algorithm family names to their quantum status.
var quantumTable = map[string]QuantumInfo{
	// Quantum-vulnerable (broken by Shor's algorithm)
	"rsa":     {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-KEM or ML-DSA"},
	"dsa":     {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-DSA"},
	"dh":      {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-KEM"},
	"ecdsa":   {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-DSA"},
	"ecdh":    {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-KEM"},
	"ec":      {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-KEM/ML-DSA"},
	"ed25519": {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-DSA"},
	"ed448":   {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-DSA"},
	"x25519":  {Status: types.QuantumVulnerable, NistLevel: 0, Recommendation: "Migrate to ML-KEM"},

	// Quantum-safe symmetric (Grover's: halves effective key size)
	"aes":      {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "AES is quantum-safe; prefer AES-256 for post-quantum margin"},
	"aes-128":  {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "Consider AES-256 for post-quantum margin"},
	"aes-192":  {Status: types.QuantumSafe, NistLevel: 3, Recommendation: "Adequate post-quantum security"},
	"aes-256":  {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "Recommended for post-quantum"},
	"chacha20": {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "256-bit key provides adequate PQ margin"},
	"camellia": {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "Quantum-safe symmetric cipher"},

	// Quantum-safe hash (Grover's: effectively halves digest size)
	"sha-256":  {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "128-bit PQ security"},
	"sha-384":  {Status: types.QuantumSafe, NistLevel: 3, Recommendation: "192-bit PQ security"},
	"sha-512":  {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "256-bit PQ security"},
	"sha3-256": {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "128-bit PQ security"},
	"sha3-384": {Status: types.QuantumSafe, NistLevel: 3, Recommendation: "192-bit PQ security"},
	"sha3-512": {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "256-bit PQ security"},
	"blake2b":  {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "Adequate PQ security"},
	"blake2s":  {Status: types.QuantumSafe, NistLevel: 1, Recommendation: "Adequate PQ security"},

	// Broken (classically broken, not just quantum)
	"md5":  {Status: types.Broken, NistLevel: 0, Recommendation: "Do not use — collision attacks practical since 2004"},
	"sha1": {Status: types.Broken, NistLevel: 0, Recommendation: "Do not use — collision attacks practical since 2017"},
	"des":  {Status: types.Broken, NistLevel: 0, Recommendation: "Do not use — 56-bit key is trivially brutable"},
	"3des": {Status: types.Broken, NistLevel: 0, Recommendation: "Deprecated by NIST — migrate to AES"},
	"rc4":  {Status: types.Broken, NistLevel: 0, Recommendation: "Do not use — multiple practical attacks"},

	// Post-quantum algorithms (NIST standards)
	"ml-kem":  {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "NIST PQC standard — recommended"},
	"ml-dsa":  {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "NIST PQC standard — recommended"},
	"slh-dsa": {Status: types.QuantumSafe, NistLevel: 5, Recommendation: "NIST PQC standard — stateless hash-based"},
}

// GetQuantumInfo returns the quantum readiness info for a given algorithm family.
// The algorithm family name is matched case-insensitively.
// Returns QuantumUnknown status if the algorithm is not recognized.
func GetQuantumInfo(algorithmFamily string) QuantumInfo {
	key := strings.ToLower(algorithmFamily)
	if info, ok := quantumTable[key]; ok {
		return info
	}
	return QuantumInfo{
		Status:         types.QuantumUnknown,
		NistLevel:      0,
		Recommendation: "Algorithm not recognized — review manually",
	}
}
