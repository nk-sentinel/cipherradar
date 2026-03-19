package rust

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single file scope
// for simple intra-procedural constant propagation in Rust.
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
//	let algo = "AES-256-CBC";
//	let key_size: usize = 2048;
//	const KEY_SIZE: usize = 4096;
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
	case "let_declaration":
		// let name = value; or let name: type = value;
		cp.processLetDecl(node, content)
	case "const_item":
		// const NAME: type = value;
		cp.processConstItem(node, content)
	case "static_item":
		// static NAME: type = value;
		cp.processStaticItem(node, content)
	}

	// Recurse into children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			cp.walkNode(child, content)
		}
	}
}

func (cp *ConstPropagator) processLetDecl(node *sitter.Node, content []byte) {
	// let_declaration: let pattern (: type)? = value
	patternNode := node.ChildByFieldName("pattern")
	valueNode := node.ChildByFieldName("value")

	if patternNode == nil || valueNode == nil {
		return
	}

	varName := extractRustIdentifier(patternNode, content)
	if varName == "" {
		return
	}

	value := extractRustLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[varName] = value
	}
}

func (cp *ConstPropagator) processConstItem(node *sitter.Node, content []byte) {
	// const_item: const NAME: type = value
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	name := nameNode.Content(content)
	value := extractRustLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[name] = value
	}
}

func (cp *ConstPropagator) processStaticItem(node *sitter.Node, content []byte) {
	// static_item: static (mut)? NAME: type = value
	nameNode := node.ChildByFieldName("name")
	valueNode := node.ChildByFieldName("value")

	if nameNode == nil || valueNode == nil {
		return
	}

	name := nameNode.Content(content)
	value := extractRustLiteralValue(valueNode, content)
	if value != "" {
		cp.vars[name] = value
	}
}

// extractRustIdentifier extracts an identifier name from a pattern node.
func extractRustIdentifier(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	if node.Type() == "identifier" {
		return node.Content(content)
	}

	// For mutable patterns: mut x
	if node.Type() == "mut_pattern" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				return child.Content(content)
			}
		}
	}

	return ""
}

// extractRustLiteralValue extracts a literal value from a tree-sitter node.
func extractRustLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string_literal":
		raw := node.Content(content)
		return unquoteRustString(raw)
	case "integer_literal":
		raw := node.Content(content)
		// Strip type suffixes like u32, i64, usize, etc.
		for _, suffix := range []string{"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize"} {
			raw = strings.TrimSuffix(raw, suffix)
		}
		// Strip underscore separators
		raw = strings.ReplaceAll(raw, "_", "")
		return raw
	case "boolean_literal":
		return node.Content(content)
	default:
		return ""
	}
}

// unquoteRustString removes surrounding quotes from a Rust string literal.
func unquoteRustString(raw string) string {
	if len(raw) < 2 {
		return raw
	}

	// Regular string: "..."
	if raw[0] == '"' && raw[len(raw)-1] == '"' {
		return raw[1 : len(raw)-1]
	}

	// Raw string: r"..." or r#"..."#
	if strings.HasPrefix(raw, "r") {
		trimmed := strings.TrimPrefix(raw, "r")
		// Count and strip #
		hashes := 0
		for _, c := range trimmed {
			if c == '#' {
				hashes++
			} else {
				break
			}
		}
		if hashes > 0 {
			trimmed = trimmed[hashes:]
		}
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1-hashes] == '"' {
			return trimmed[1 : len(trimmed)-1-hashes]
		}
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			return trimmed[1 : len(trimmed)-1]
		}
	}

	return raw
}
