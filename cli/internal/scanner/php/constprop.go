package php

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in PHP.
//
// It handles patterns like:
//
//	$algo = 'AES-256-CBC';
//	$method = "sha256";
//	$iterations = 10000;
type ConstPropagator struct {
	vars map[string]string // variable name (without $) -> resolved string/integer value
}

// NewConstPropagator creates a new constant propagator.
func NewConstPropagator() *ConstPropagator {
	return &ConstPropagator{
		vars: make(map[string]string),
	}
}

// Resolve attempts to resolve a variable name to its constant string value.
// The name should be without the $ prefix.
// Returns the resolved value and true if found, or empty string and false otherwise.
func (cp *ConstPropagator) Resolve(name string) (string, bool) {
	val, ok := cp.vars[name]
	return val, ok
}

// Set stores a variable-value binding.
func (cp *ConstPropagator) Set(name, value string) {
	cp.vars[name] = value
}

// CollectAssignments walks the tree-sitter AST and collects simple assignments
// where the right-hand side is a string literal or integer literal.
// It also performs a line-based fallback scan for PHP variable assignments
// that the AST walk might miss due to grammar differences.
func (cp *ConstPropagator) CollectAssignments(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}
	cp.walkNode(node, content)

	// Fallback: scan source text for PHP variable assignments
	cp.scanPHPAssignments(content)
}

func (cp *ConstPropagator) walkNode(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}

	// PHP tree-sitter grammar uses "assignment_expression" for $var = value
	if node.Type() == "assignment_expression" {
		cp.processAssignment(node, content)
	}

	// Recurse into children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			cp.walkNode(child, content)
		}
	}
}

func (cp *ConstPropagator) processAssignment(node *sitter.Node, content []byte) {
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	// In PHP grammar, the left side of $var = ... is a "variable_name" node
	// containing "$varname", or it might be wrapped in another node type.
	varName := extractVarName(leftNode, content)
	if varName == "" {
		return
	}

	value := extractLiteralValue(rightNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

// extractVarName extracts the variable name (without $) from a PHP variable node.
func extractVarName(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	text := node.Content(content)
	if strings.HasPrefix(text, "$") {
		return strings.TrimPrefix(text, "$")
	}

	// Walk children to find the variable_name
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			childText := child.Content(content)
			if strings.HasPrefix(childText, "$") {
				return strings.TrimPrefix(childText, "$")
			}
		}
	}

	return ""
}

// extractLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for integer literals.
// Returns empty string if the node is not a simple literal.
func extractLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string":
		raw := node.Content(content)
		return unquotePHPString(raw)
	case "encapsed_string":
		raw := node.Content(content)
		return unquotePHPString(raw)
	case "integer":
		return node.Content(content)
	default:
		return ""
	}
}

// scanPHPAssignments performs a simple line-based scan of the source code
// to extract PHP variable assignments that the AST walk might miss.
// Handles patterns like:
//
//	$algo = 'AES-256-CBC';
//	$method = "sha256";
//	$iterations = 10000;
func (cp *ConstPropagator) scanPHPAssignments(content []byte) {
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		cp.parsePHPAssignment(trimmed)
	}
}

// parsePHPAssignment tries to extract a variable binding from a PHP assignment line.
func (cp *ConstPropagator) parsePHPAssignment(line string) {
	// Must start with $
	if !strings.HasPrefix(line, "$") {
		return
	}

	// Find the = sign
	eqIdx := strings.Index(line, "=")
	if eqIdx < 0 {
		return
	}
	// Make sure it's not == or ===
	if eqIdx+1 < len(line) && line[eqIdx+1] == '=' {
		return
	}

	varPart := strings.TrimSpace(line[1:eqIdx]) // strip $ prefix
	valuePart := strings.TrimSpace(line[eqIdx+1:])

	// Strip trailing semicolon
	valuePart = strings.TrimRight(valuePart, ";")
	valuePart = strings.TrimSpace(valuePart)

	// Skip empty or complex assignments
	if varPart == "" || valuePart == "" {
		return
	}

	// Skip if variable name contains non-identifier characters
	if strings.ContainsAny(varPart, " \t(){}[]->") {
		return
	}

	// Already have this from AST walk — don't overwrite
	if _, exists := cp.vars[varPart]; exists {
		return
	}

	// Extract string literal value (single or double quotes)
	if len(valuePart) >= 2 {
		if (valuePart[0] == '\'' && valuePart[len(valuePart)-1] == '\'') ||
			(valuePart[0] == '"' && valuePart[len(valuePart)-1] == '"') {
			cp.vars[varPart] = valuePart[1 : len(valuePart)-1]
			return
		}
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
