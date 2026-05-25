package opengrep

// CanonicalizePrimitive is the public entry point to the algorithm-token
// canonicalizer used internally by the OpenGrep finding parser. It's
// exported so the YARA-X parser (cli/internal/scanner/yarax) can map
// `cbom_primitive` meta values to the same canonical vocabulary
// without duplicating the rule set.
//
// Returns "" when the input doesn't look like a recognized crypto
// token; see canonicalizePrimitive for the full token list and
// normalization rules.
func CanonicalizePrimitive(s string) string {
	return canonicalizePrimitive(s)
}
