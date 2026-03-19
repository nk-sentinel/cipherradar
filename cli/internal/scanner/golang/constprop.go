package golang

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in Go.
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
//	var algo = "AES"
//	const algo = "AES/CBC/PKCS5Padding"
//	algo := "AES"
//	keySize := 2048
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
	case "var_spec":
		// var name = value or var name type = value
		cp.processVarSpec(node, content)
	case "const_spec":
		// const name = value or const name type = value
		cp.processConstSpec(node, content)
	case "short_var_declaration":
		// name := value
		cp.processShortVarDecl(node, content)
	case "assignment_statement":
		// name = value
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

func (cp *ConstPropagator) processVarSpec(node *sitter.Node, content []byte) {
	// var_spec: name (type)? = value
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	varName := nameNode.Content(content)
	value := extractGoLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

func (cp *ConstPropagator) processConstSpec(node *sitter.Node, content []byte) {
	// const_spec: name (type)? = value
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	varName := nameNode.Content(content)
	value := extractGoLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

func (cp *ConstPropagator) processShortVarDecl(node *sitter.Node, content []byte) {
	// short_var_declaration: left := right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	// Handle single identifier on the left (expression_list with one identifier)
	names := extractIdentifiers(leftNode, content)
	values := extractExpressionListValues(rightNode, content)

	for i := 0; i < len(names) && i < len(values); i++ {
		if values[i] != "" {
			cp.vars[names[i]] = values[i]
		}
	}
}

func (cp *ConstPropagator) processAssignment(node *sitter.Node, content []byte) {
	// assignment_statement: left = right
	leftNode := node.ChildByFieldName("left")
	rightNode := node.ChildByFieldName("right")

	if leftNode == nil || rightNode == nil {
		return
	}

	names := extractIdentifiers(leftNode, content)
	values := extractExpressionListValues(rightNode, content)

	for i := 0; i < len(names) && i < len(values); i++ {
		if values[i] != "" {
			cp.vars[names[i]] = values[i]
		}
	}
}

// extractIdentifiers extracts identifier names from a node (which may be an
// expression_list containing multiple identifiers).
func extractIdentifiers(node *sitter.Node, content []byte) []string {
	if node == nil {
		return nil
	}

	if node.Type() == "identifier" {
		return []string{node.Content(content)}
	}

	if node.Type() == "expression_list" {
		var names []string
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				names = append(names, child.Content(content))
			}
		}
		return names
	}

	return nil
}

// extractExpressionListValues extracts literal values from an expression_list node.
func extractExpressionListValues(node *sitter.Node, content []byte) []string {
	if node == nil {
		return nil
	}

	// Single value
	if node.Type() != "expression_list" {
		return []string{extractGoLiteralValue(node, content)}
	}

	var values []string
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		nodeType := child.Type()
		if nodeType == "," {
			continue
		}
		values = append(values, extractGoLiteralValue(child, content))
	}
	return values
}

// extractGoLiteralValue extracts a literal value from a tree-sitter node.
// Returns the string content for string literals (without quotes) or
// the numeric value as a string for integer literals.
// Returns empty string if the node is not a simple literal.
func extractGoLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "interpreted_string_literal":
		raw := node.Content(content)
		return unquoteGoString(raw)
	case "raw_string_literal":
		raw := node.Content(content)
		return unquoteGoString(raw)
	case "int_literal":
		raw := node.Content(content)
		// Strip underscore separators
		raw = strings.ReplaceAll(raw, "_", "")
		return raw
	case "expression_list":
		// If the expression list has a single element, extract it
		if node.ChildCount() == 1 {
			return extractGoLiteralValue(node.Child(0), content)
		}
		return ""
	default:
		return ""
	}
}
