package types

// Location pinpoints where a finding was detected in the source code.
type Location struct {
	// File is the relative file path from the scan root.
	File string `json:"file"`
	// StartLine is the starting line number of the finding.
	StartLine int `json:"start_line"`
	// StartCol is the starting column number of the finding.
	StartCol int `json:"start_col"`
	// EndLine is the ending line number of the finding.
	EndLine int `json:"end_line"`
	// EndCol is the ending column number of the finding.
	EndCol int `json:"end_col"`
	// Snippet is the source code line(s) containing the finding.
	Snippet string `json:"snippet"`
}
