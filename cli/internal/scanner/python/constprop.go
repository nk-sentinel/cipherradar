package python

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single function scope
// for simple intra-procedural constant propagation.
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

// CollectAssignments walks the tree-sitter AST and collects simple assignments
// where the right-hand side is a string literal or integer literal.
// It handles patterns like:
//
//	algo = "AES"
//	key_size = 2048
//	hash_name = "sha256"
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

	if node.Type() == "assignment" {
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
	// An assignment node has the form: left = right
	// In tree-sitter Python grammar, assignment has named children:
	// left (pattern_list or identifier) and right (expression)
	if node.ChildCount() < 3 {
		return
	}

	// The assignment structure is: left "=" right
	// Named child "left" is at index 0, "right" is the value
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	// Only handle simple identifier = literal assignments
	if leftNode.Type() != "identifier" {
		return
	}

	varName := leftNode.Content(content)
	value := extractLiteralValue(rightNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
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
		// String node wraps the actual string content
		raw := node.Content(content)
		return unquotePythonString(raw)
	case "integer":
		return node.Content(content)
	case "concatenated_string":
		// Handle string concatenation - only if all parts are string literals
		var parts []string
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "string" {
				raw := child.Content(content)
				parts = append(parts, unquotePythonString(raw))
			} else {
				return "" // Non-literal part, bail out
			}
		}
		return strings.Join(parts, "")
	default:
		return ""
	}
}

// unquotePythonString removes surrounding quotes from a Python string literal.
// Handles single quotes, double quotes, triple quotes, and byte/raw prefixes.
func unquotePythonString(raw string) string {
	if len(raw) == 0 {
		return ""
	}

	s := raw

	// Strip prefixes (b, r, f, u, and combinations)
	for len(s) > 0 {
		ch := s[0]
		if ch == 'b' || ch == 'B' || ch == 'r' || ch == 'R' || ch == 'f' || ch == 'F' || ch == 'u' || ch == 'U' {
			s = s[1:]
		} else {
			break
		}
	}

	if len(s) < 2 {
		return raw
	}

	// Triple quotes
	if len(s) >= 6 && (s[:3] == `"""` || s[:3] == `'''`) {
		quote := s[:3]
		if strings.HasSuffix(s, quote) {
			return s[3 : len(s)-3]
		}
		return raw
	}

	// Single/double quotes
	if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}

	return raw
}
