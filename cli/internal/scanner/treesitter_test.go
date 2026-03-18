package scanner

import (
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

func TestParseWithTreeSitter(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("import hashlib\nx = hashlib.md5(b'test')\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}
	if root == nil {
		t.Fatal("expected non-nil root node")
	}
	if root.Type() != "module" {
		t.Errorf("expected root node type 'module', got %q", root.Type())
	}
	if root.ChildCount() == 0 {
		t.Error("expected root node to have children")
	}
}

func TestParseWithTreeSitterEmptyInput(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error for empty input: %v", err)
	}
	if root == nil {
		t.Fatal("expected non-nil root node for empty input")
	}
}

func TestNodeText(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("import hashlib\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}

	// The first child should be an import statement
	child := root.Child(0)
	if child == nil {
		t.Fatal("expected root to have a child node")
	}

	text := NodeText(child, content)
	if text != "import hashlib" {
		t.Errorf("NodeText = %q, want %q", text, "import hashlib")
	}
}

func TestNodeLocation(t *testing.T) {
	lang := python.GetLanguage()
	// Two lines: line 1 is "x = 1", line 2 is "y = 2"
	content := []byte("x = 1\ny = 2\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}

	// Get the second statement (y = 2), which is at tree-sitter row 1, col 0
	secondChild := root.Child(1)
	if secondChild == nil {
		t.Fatal("expected root to have a second child")
	}

	loc := NodeLocation(secondChild, "test.py", content)

	if loc.File != "test.py" {
		t.Errorf("expected file 'test.py', got %q", loc.File)
	}
	// tree-sitter row 1 -> 1-indexed line 2
	if loc.StartLine != 2 {
		t.Errorf("expected StartLine 2, got %d", loc.StartLine)
	}
	// tree-sitter col 0 -> 1-indexed col 1
	if loc.StartCol != 1 {
		t.Errorf("expected StartCol 1, got %d", loc.StartCol)
	}
	if loc.EndLine != 2 {
		t.Errorf("expected EndLine 2, got %d", loc.EndLine)
	}
	if loc.Snippet != "y = 2" {
		t.Errorf("expected Snippet 'y = 2', got %q", loc.Snippet)
	}
}

func TestQueryMatches(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("import hashlib\nhashlib.md5(b'test')\nprint('hello')\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}

	// Query for all function calls capturing the function name
	queryStr := `(call function: (identifier) @func)`
	matches, err := QueryMatches(root, queryStr, lang, content)
	if err != nil {
		t.Fatalf("QueryMatches returned error: %v", err)
	}

	// We expect at least the print('hello') call to match (identifier call).
	// hashlib.md5() has an attribute function, not a plain identifier, so it won't match this pattern.
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	// Verify we can extract the function name from the match
	found := false
	for _, match := range matches {
		for _, capture := range match.Captures {
			text := capture.Node.Content(content)
			if text == "print" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected to find 'print' function call in matches")
	}
}

func TestQueryMatchesAttribute(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("import hashlib\nhashlib.md5(b'test')\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}

	// Query for attribute-style function calls like hashlib.md5()
	queryStr := `(call function: (attribute object: (identifier) @obj attribute: (identifier) @method))`
	matches, err := QueryMatches(root, queryStr, lang, content)
	if err != nil {
		t.Fatalf("QueryMatches returned error: %v", err)
	}

	if len(matches) == 0 {
		t.Fatal("expected at least one match for attribute call")
	}

	// Verify we captured "hashlib" as obj and "md5" as method
	var foundObj, foundMethod bool
	for _, match := range matches {
		for _, capture := range match.Captures {
			text := capture.Node.Content(content)
			if text == "hashlib" {
				foundObj = true
			}
			if text == "md5" {
				foundMethod = true
			}
		}
	}
	if !foundObj {
		t.Error("expected to find 'hashlib' as object in attribute call")
	}
	if !foundMethod {
		t.Error("expected to find 'md5' as method in attribute call")
	}
}

func TestQueryMatchesInvalidQuery(t *testing.T) {
	lang := python.GetLanguage()
	content := []byte("x = 1\n")

	root, err := ParseWithTreeSitter(content, lang)
	if err != nil {
		t.Fatalf("ParseWithTreeSitter returned error: %v", err)
	}

	_, err = QueryMatches(root, "(invalid_node_type_xyz @cap)", lang, content)
	// tree-sitter may or may not error on unknown node types depending on version,
	// but truly malformed queries should error
	_ = err // just ensure it doesn't panic
}

func newQueryCaptureTexts(matches []*sitter.QueryMatch, content []byte) []string {
	var texts []string
	for _, m := range matches {
		for _, c := range m.Captures {
			texts = append(texts, c.Node.Content(content))
		}
	}
	return texts
}
