package ruby

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstPropagator tracks variable assignments within a single Ruby file scope
// for simple intra-procedural constant propagation.
//
// It handles patterns like:
//
//	algo = "AES-256-CBC"
//	key_size = 2048
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
// Also performs a line-based fallback scan.
func (cp *ConstPropagator) CollectAssignments(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}
	cp.walkNode(node, content)

	// Fallback: scan source lines for Ruby variable assignments
	cp.scanRubyAssignments(content)
}

func (cp *ConstPropagator) walkNode(node *sitter.Node, content []byte) {
	if node == nil {
		return
	}

	// Ruby tree-sitter grammar uses "assignment" for var = value
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
func extractLiteralValue(node *sitter.Node, content []byte) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "string":
		raw := node.Content(content)
		return unquoteRubyString(raw)
	case "integer":
		return node.Content(content)
	default:
		return ""
	}
}

// scanRubyAssignments performs a simple line-based scan of the source code
// to extract Ruby variable assignments that the AST walk might miss.
func (cp *ConstPropagator) scanRubyAssignments(content []byte) {
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		cp.parseRubyAssignment(trimmed)
	}
}

// parseRubyAssignment tries to extract a variable binding from a Ruby assignment line.
func (cp *ConstPropagator) parseRubyAssignment(line string) {
	// Skip comments
	if strings.HasPrefix(line, "#") {
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
	// Make sure it's not !=, <=, >=
	if eqIdx > 0 && (line[eqIdx-1] == '!' || line[eqIdx-1] == '<' || line[eqIdx-1] == '>') {
		return
	}

	varPart := strings.TrimSpace(line[:eqIdx])
	valuePart := strings.TrimSpace(line[eqIdx+1:])

	// Skip if variable name contains non-identifier characters
	if varPart == "" || strings.ContainsAny(varPart, " \t(){}[]@$") {
		return
	}

	// Already have this from AST walk -- don't overwrite
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
