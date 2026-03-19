package kotlin

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in Kotlin.
//
// Because the scanner uses the Java tree-sitter grammar to parse Kotlin,
// Kotlin-specific declaration syntax (val, const val, var) is not directly
// recognized as AST nodes. Instead, the Java grammar parses these as
// identifiers and expressions. This propagator handles both Java-style
// AST nodes (variable_declarator, assignment_expression) for cases where
// the grammar produces them, and a fallback text-based approach for
// Kotlin-specific patterns like "val algo = ..." and "const val ALGO = ...".
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

// CollectAssignments walks the tree-sitter AST and collects simple variable
// declarations where the right-hand side is a string literal or integer literal.
// It handles Java-grammar AST patterns for code parsed with the Java grammar,
// plus a source-text scan for Kotlin patterns like:
//
//	val algo = "AES"
//	const val ALGORITHM = "AES/CBC/PKCS5Padding"
//	var mode = "GCM"
func (cp *ConstPropagator) CollectAssignments(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}
	cp.walkNode(node, content)

	// Fallback: scan source text for Kotlin val/var/const val patterns
	// that the Java grammar may not parse into standard variable_declarator nodes.
	cp.scanKotlinDeclarations(content)
}

func (cp *ConstPropagator) walkNode(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}

	switch node.Type() {
	case "variable_declarator":
		cp.processVariableDeclarator(node, content)
	case "assignment_expression":
		cp.processAssignmentExpression(node, content)
	}

	// Recurse into children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			cp.walkNode(child, content)
		}
	}
}

func (cp *ConstPropagator) processVariableDeclarator(node *sitter.Node, content []byte) {
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	if nameNode.Type() != "identifier" {
		return
	}

	varName := nameNode.Content(content)
	value := extractLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

func (cp *ConstPropagator) processAssignmentExpression(node *sitter.Node, content []byte) {
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	if leftNode.Type() != "identifier" {
		return
	}

	varName := leftNode.Content(content)
	value := extractLiteralValue(rightNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

// scanKotlinDeclarations performs a simple line-based scan of the source code
// to extract Kotlin-specific val/var/const val declarations that the Java
// grammar might not parse into recognizable AST nodes.
func (cp *ConstPropagator) scanKotlinDeclarations(content []byte) {
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		cp.parseKotlinValDecl(trimmed)
	}
}

// parseKotlinValDecl tries to extract a variable binding from a Kotlin-style
// declaration line like:
//
//	val algo = "AES"
//	const val ALGORITHM = "AES/CBC/PKCS5Padding"
//	var mode = "GCM"
func (cp *ConstPropagator) parseKotlinValDecl(line string) {
	// Strip "const " prefix if present
	stripped := line
	if strings.HasPrefix(stripped, "const ") {
		stripped = strings.TrimPrefix(stripped, "const ")
	}

	// Must start with "val " or "var "
	var rest string
	if strings.HasPrefix(stripped, "val ") {
		rest = strings.TrimPrefix(stripped, "val ")
	} else if strings.HasPrefix(stripped, "var ") {
		rest = strings.TrimPrefix(stripped, "var ")
	} else {
		return
	}

	// Split on " = " to get name and value
	eqIdx := strings.Index(rest, " = ")
	if eqIdx < 0 {
		// Try "=" without spaces
		eqIdx = strings.Index(rest, "=")
		if eqIdx < 0 {
			return
		}
	}

	namePart := strings.TrimSpace(rest[:eqIdx])
	valuePart := strings.TrimSpace(rest[eqIdx+1:])
	if strings.Contains(valuePart, "=") && !strings.HasPrefix(valuePart, "\"") {
		// Avoid false positives from "= =" patterns
		valuePart = strings.TrimPrefix(valuePart, "= ")
		valuePart = strings.TrimSpace(valuePart)
	}

	// Strip type annotation: "algo: String" -> "algo"
	if colonIdx := strings.Index(namePart, ":"); colonIdx >= 0 {
		namePart = strings.TrimSpace(namePart[:colonIdx])
	}

	// Only keep simple identifiers
	if namePart == "" || strings.ContainsAny(namePart, " \t(){}[]") {
		return
	}

	// Extract string literal value
	if strings.HasPrefix(valuePart, "\"") && strings.HasSuffix(valuePart, "\"") && len(valuePart) >= 2 {
		cp.vars[namePart] = valuePart[1 : len(valuePart)-1]
		return
	}

	// Extract integer literal value
	if isIntLiteral(valuePart) {
		cp.vars[namePart] = valuePart
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

// extractLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for integer/decimal literals.
// Returns empty string if the node is not a simple literal.
func extractLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string_literal":
		raw := node.Content(content)
		return unquoteString(raw)
	case "decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal":
		raw := node.Content(content)
		// Strip trailing L/l suffix
		raw = strings.TrimRight(raw, "Ll")
		return raw
	case "decimal_floating_point_literal":
		return node.Content(content)
	default:
		return ""
	}
}
