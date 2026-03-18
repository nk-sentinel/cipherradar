package javascript

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in JavaScript/TypeScript.
type ConstPropagator struct {
	vars map[string]string // variable name -> resolved string/number value
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
// declarations where the right-hand side is a string literal or number literal.
// It handles patterns like:
//
//	const algo = 'sha256';
//	let mode = "aes-256-cbc";
//	var keySize = 2048;
//	const config = { algorithm: 'sha256' };
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
	// variable_declarator has "name" and "value" fields
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

	// If the value is an object, extract property literals
	if valueNode.Type() == "object" {
		cp.extractObjectProperties(varName, valueNode, content)
		return
	}

	value := extractJSLiteralValue(valueNode, content)
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
	value := extractJSLiteralValue(rightNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

// extractObjectProperties extracts simple property values from an object literal.
// For { algorithm: 'sha256', bits: 2048 }, stores "config.algorithm" -> "sha256", etc.
func (cp *ConstPropagator) extractObjectProperties(objName string, objNode *sitter.Node, content []byte) {
	for i := 0; i < int(objNode.ChildCount()); i++ {
		child := objNode.Child(i)
		if child == nil {
			continue
		}
		if child.Type() == "pair" {
			keyNode := child.ChildByFieldName("key")
			valueNode := child.ChildByFieldName("value")
			if keyNode == nil || valueNode == nil {
				continue
			}

			var keyName string
			switch keyNode.Type() {
			case "property_identifier":
				keyName = keyNode.Content(content)
			case "string", "string_fragment":
				keyName = unquoteJSString(keyNode.Content(content))
			default:
				continue
			}

			value := extractJSLiteralValue(valueNode, content)
			if value != "" && keyName != "" {
				cp.vars[objName+"."+keyName] = value
			}
		}
	}
}

// extractJSLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for number literals.
// Returns empty string if the node is not a simple literal.
func extractJSLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string":
		// String node contains the quotes; extract the inner content
		raw := node.Content(content)
		return unquoteJSString(raw)
	case "template_string":
		// Template strings with no interpolation: `sha256`
		raw := node.Content(content)
		if len(raw) >= 2 && raw[0] == '`' && raw[len(raw)-1] == '`' {
			inner := raw[1 : len(raw)-1]
			// Only handle simple template strings with no interpolation
			if !strings.Contains(inner, "${") {
				return inner
			}
		}
		return ""
	case "number":
		return node.Content(content)
	default:
		return ""
	}
}

// unquoteJSString removes surrounding quotes from a JavaScript string literal.
// Handles single quotes, double quotes.
func unquoteJSString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	if (raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'') {
		return raw[1 : len(raw)-1]
	}

	return raw
}
