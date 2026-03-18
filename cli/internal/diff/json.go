package diff

import (
	"encoding/json"
	"io"
)

// jsonDiffOutput is the JSON serialization format for a diff result.
type jsonDiffOutput struct {
	Before  string               `json:"before"`
	After   string               `json:"after"`
	Summary jsonDiffSummary      `json:"summary"`
	Added   []jsonComponent      `json:"added"`
	Removed []jsonComponent      `json:"removed"`
	Changed []jsonChangedComponent `json:"changed"`
}

// jsonDiffSummary holds the counts for each diff category.
type jsonDiffSummary struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

// jsonComponent is a simplified component for JSON diff output.
type jsonComponent struct {
	BOMRef   string `json:"bomRef,omitempty"`
	Name     string `json:"name"`
	Location string `json:"location,omitempty"`
}

// jsonChangedComponent describes a changed component in JSON output.
type jsonChangedComponent struct {
	BOMRef  string   `json:"bomRef,omitempty"`
	Name    string   `json:"name"`
	Changes []string `json:"changes"`
}

// FormatJSON writes the diff as JSON to the writer.
func FormatJSON(w io.Writer, result *DiffResult) error {
	out := jsonDiffOutput{
		Before: result.Before,
		After:  result.After,
		Summary: jsonDiffSummary{
			Added:     len(result.Added),
			Removed:   len(result.Removed),
			Changed:   len(result.Changed),
			Unchanged: result.Unchanged,
		},
		Added:   make([]jsonComponent, 0, len(result.Added)),
		Removed: make([]jsonComponent, 0, len(result.Removed)),
		Changed: make([]jsonChangedComponent, 0, len(result.Changed)),
	}

	for _, c := range result.Added {
		out.Added = append(out.Added, jsonComponent{
			BOMRef:   c.BOMRef,
			Name:     c.Name,
			Location: firstLocation(&c),
		})
	}

	for _, c := range result.Removed {
		out.Removed = append(out.Removed, jsonComponent{
			BOMRef:   c.BOMRef,
			Name:     c.Name,
			Location: firstLocation(&c),
		})
	}

	for _, cc := range result.Changed {
		out.Changed = append(out.Changed, jsonChangedComponent{
			BOMRef:  cc.BOMRef,
			Name:    cc.Name,
			Changes: cc.Changes,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
