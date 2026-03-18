package java

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in Java.
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
// It handles patterns like:
//
//	String algo = "AES";
//	final String ALGORITHM = "AES/CBC/PKCS5Padding";
//	int keySize = 2048;
func (cp *ConstPropagator) CollectAssignments(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}
	cp.walkNode(node, content)
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
	// variable_declarator has "name" and "value" fields in the Java grammar
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	// Only handle simple identifier = literal assignments
	if nameNode.Type() != "identifier" {
		return
	}

	varName := nameNode.Content(content)
	value := extractJavaLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

func (cp *ConstPropagator) processAssignmentExpression(node *sitter.Node, content []byte) {
	// assignment_expression has "left" and "right" fields
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	if leftNode.Type() != "identifier" {
		return
	}

	varName := leftNode.Content(content)
	value := extractJavaLiteralValue(rightNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

// extractJavaLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for integer/decimal literals.
// Returns empty string if the node is not a simple literal.
func extractJavaLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string_literal":
		raw := node.Content(content)
		return unquoteJavaString(raw)
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

// unquoteJavaString removes surrounding double quotes from a Java string literal.
func unquoteJavaString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}

	return raw
}
