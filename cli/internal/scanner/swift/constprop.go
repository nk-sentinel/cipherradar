package swift

import (
	"strings"
)

// ConstPropagator tracks variable assignments within a single Swift file scope
// for simple intra-procedural constant propagation.
//
// It handles patterns like:
//
//	let algorithm = "AES"
//	var keySize = 256
type ConstPropagator struct {
	vars map[string]string // variable name -> resolved string/integer value
}

// NewConstPropagator creates a new constant propagator.
func NewConstPropagator() *ConstPropagator {
	return &ConstPropagator{
		vars: make(map[string]string),
	}
}

// Resolve attempts to resolve a variable name to its constant string value.
// Returns the resolved value and true if found, or empty string and false otherwise.
func (cp *ConstPropagator) Resolve(name string) (string, bool) {
	val, ok := cp.vars[name]
	return val, ok
}

// Set stores a variable-value binding.
func (cp *ConstPropagator) Set(name, value string) {
	cp.vars[name] = value
}

// CollectAssignments scans Swift source lines to collect simple let/var assignments
// where the right-hand side is a string or integer literal.
func (cp *ConstPropagator) CollectAssignments(content []byte) {
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		cp.parseSwiftAssignment(trimmed)
	}
}

// ResolveLine replaces known variable names in the line with their constant values.
// This is best-effort: it only replaces simple identifier references.
func (cp *ConstPropagator) ResolveLine(line string) string {
	result := line
	for varName, value := range cp.vars {
		result = strings.ReplaceAll(result, varName, value)
	}
	return result
}

// parseSwiftAssignment tries to extract a variable binding from a Swift let/var assignment.
func (cp *ConstPropagator) parseSwiftAssignment(line string) {
	// Must start with let or var
	var rest string
	if strings.HasPrefix(line, "let ") {
		rest = strings.TrimPrefix(line, "let ")
	} else if strings.HasPrefix(line, "var ") {
		rest = strings.TrimPrefix(line, "var ")
	} else {
		return
	}

	// Find the = sign (skip type annotations)
	eqIdx := strings.Index(rest, "=")
	if eqIdx < 0 {
		return
	}
	// Make sure it's not ==
	if eqIdx+1 < len(rest) && rest[eqIdx+1] == '=' {
		return
	}

	varPart := strings.TrimSpace(rest[:eqIdx])
	valuePart := strings.TrimSpace(rest[eqIdx+1:])

	// Strip type annotation from variable name (e.g., "algo: String")
	if colonIdx := strings.Index(varPart, ":"); colonIdx >= 0 {
		varPart = strings.TrimSpace(varPart[:colonIdx])
	}

	// Skip empty or complex variable names
	if varPart == "" || strings.ContainsAny(varPart, " \t(){}[]") {
		return
	}

	// Skip if already have this
	if _, exists := cp.vars[varPart]; exists {
		return
	}

	// Extract string literal value
	if len(valuePart) >= 2 && valuePart[0] == '"' && valuePart[len(valuePart)-1] == '"' {
		cp.vars[varPart] = valuePart[1 : len(valuePart)-1]
		return
	}

	// Extract integer literal value
	if isIntLiteral(valuePart) {
		cp.vars[varPart] = valuePart
	}
}

// isIntLiteral checks if a string looks like an integer literal.
func isIntLiteral(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
