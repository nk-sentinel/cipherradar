// Package kdf provides shared helpers for checking KDF (Key Derivation Function)
// parameters across all language scanners.
package kdf

import "github.com/nk-sentinel/cipherradar/cli/internal/types"

// MinPBKDF2Iterations is the minimum recommended iteration count for PBKDF2.
const MinPBKDF2Iterations = 100000

// MinBcryptCost is the minimum recommended cost factor for bcrypt.
const MinBcryptCost = 10

// CheckKDFIterations evaluates whether a KDF's iteration/cost parameter is
// sufficient. It returns a severity and a human-readable message. If the
// parameters are adequate, severity is SeverityInfo with an empty message.
func CheckKDFIterations(algorithm string, iterations int) (severity types.Severity, message string) {
	if iterations <= 0 {
		// Unable to determine; do not flag.
		return types.SeverityInfo, ""
	}

	switch algorithm {
	case "pbkdf2":
		if iterations < MinPBKDF2Iterations {
			return types.SeverityMedium, "PBKDF2 iteration count is below recommended minimum of 100000"
		}
	case "bcrypt":
		if iterations < MinBcryptCost {
			return types.SeverityMedium, "bcrypt cost factor is below recommended minimum of 10"
		}
	}

	return types.SeverityInfo, ""
}
