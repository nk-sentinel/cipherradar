package cpp

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in C/C++.
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
// declarations where the right-hand side is a string literal, integer literal,
// or a known identifier. It handles patterns like:
//
//	int keySize = 2048;
//	const char *algo = "AES-256-CBC";
//	#define KEY_SIZE 2048
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
	case "declaration":
		// int x = 42; or const char *algo = "AES";
		cp.processDeclaration(node, content)
	case "init_declarator":
		// x = 42 within a declaration
		cp.processInitDeclarator(node, content)
	case "assignment_expression":
		// x = 42;
		cp.processAssignment(node, content)
	case "preproc_def":
		// #define KEY_SIZE 2048
		cp.processPreprocessorDefine(node, content)
	}

	// Recurse into children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			cp.walkNode(child, content)
		}
	}
}

func (cp *ConstPropagator) processDeclaration(node *sitter.Node, content []byte) {
	// Walk children for init_declarator
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == "init_declarator" {
			cp.processInitDeclarator(child, content)
		}
	}
}

func (cp *ConstPropagator) processInitDeclarator(node *sitter.Node, content []byte) {
	// init_declarator: declarator = value
	declarator := node.ChildByFieldName("declarator")
	value := node.ChildByFieldName("value")

	if declarator == nil || value == nil {
		return
	}

	varName := extractDeclaratorName(declarator, content)
	if varName == "" {
		return
	}

	litValue := extractCLiteralValue(value, content)
	if litValue != "" {
		cp.vars[varName] = litValue
	}
}

func (cp *ConstPropagator) processAssignment(node *sitter.Node, content []byte) {
	// assignment_expression: left = right
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")

	if left == nil || right == nil {
		return
	}

	if left.Type() == "identifier" {
		varName := left.Content(content)
		litValue := extractCLiteralValue(right, content)
		if litValue != "" {
			cp.vars[varName] = litValue
		}
	}
}

func (cp *ConstPropagator) processPreprocessorDefine(node *sitter.Node, content []byte) {
	// preproc_def: #define NAME VALUE
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	name := nameNode.Content(content)
	value := strings.TrimSpace(valueNode.Content(content))
	if value != "" {
		cp.vars[name] = value
	}
}

// extractDeclaratorName extracts the variable name from a declarator node,
// handling pointer declarators (e.g., *algo -> algo).
func extractDeclaratorName(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "identifier":
		return node.Content(content)
	case "pointer_declarator":
		// Recurse into the declarator child
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				return child.Content(content)
			}
		}
		// Try the declarator field
		decl := node.ChildByFieldName("declarator")
		if decl != nil {
			return extractDeclaratorName(decl, content)
		}
	}

	return ""
}

// extractCLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for number literals.
// Returns empty string if the node is not a simple literal.
func extractCLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string_literal":
		raw := node.Content(content)
		return unquoteCString(raw)
	case "number_literal":
		raw := node.Content(content)
		// Strip suffixes like L, UL, etc.
		raw = strings.TrimRight(raw, "lLuUfF")
		return raw
	case "char_literal":
		raw := node.Content(content)
		return unquoteCString(raw)
	case "identifier":
		// Return the identifier text for further resolution
		return node.Content(content)
	default:
		return ""
	}
}

// unquoteCString removes surrounding quotes from a C string literal.
func unquoteCString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	// String literal: "..."
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}

	// Char literal: '...'
	if raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1]
	}

	return raw
}
