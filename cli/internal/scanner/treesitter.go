package scanner

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ParseWithTreeSitter parses source code using the given tree-sitter language and returns the root node.
func ParseWithTreeSitter(content []byte, lang *sitter.Language) (*sitter.Node, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(lang)
	tree, err := parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse error: %w", err)
	}
	return tree.RootNode(), nil
}

// QueryMatches runs a tree-sitter query against a node and returns all matches.
func QueryMatches(node *sitter.Node, queryStr string, lang *sitter.Language, content []byte) ([]*sitter.QueryMatch, error) {
	query, err := sitter.NewQuery([]byte(queryStr), lang)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter query error: %w", err)
	}
	cursor := sitter.NewQueryCursor()
	cursor.Exec(query, node)

	var matches []*sitter.QueryMatch
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}
		match = cursor.FilterPredicates(match, content)
		matches = append(matches, match)
	}
	return matches, nil
}

// NodeText extracts the text content of a tree-sitter node.
func NodeText(node *sitter.Node, content []byte) string {
	return node.Content(content)
}

// NodeLocation converts a tree-sitter node to a types.Location.
func NodeLocation(node *sitter.Node, path string, content []byte) types.Location {
	return types.Location{
		File:      path,
		StartLine: int(node.StartPoint().Row) + 1, // tree-sitter is 0-indexed
		StartCol:  int(node.StartPoint().Column) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
		EndCol:    int(node.EndPoint().Column) + 1,
		Snippet:   node.Content(content),
	}
}
