package types

import "time"

// ScanResult holds the complete output of a scan operation.
type ScanResult struct {
	// Target is the path or URL that was scanned.
	Target string `json:"target"`
	// Findings is the list of cryptographic assets detected.
	Findings []Finding `json:"findings"`
	// StartTime is when the scan began.
	StartTime time.Time `json:"start_time"`
	// EndTime is when the scan completed.
	EndTime time.Time `json:"end_time"`
	// PassesRun lists which scanner passes were executed (e.g. [1, 2]).
	PassesRun []int `json:"passes_run"`
	// FilesScanned is the total number of files analyzed.
	FilesScanned int `json:"files_scanned"`
	// Errors lists non-fatal errors encountered during scanning.
	Errors []ScanError `json:"errors"`
}

// ScanError represents a non-fatal error encountered while scanning a file.
type ScanError struct {
	// File is the path of the file where the error occurred.
	File string `json:"file"`
	// Message is a human-readable description of the error.
	Message string `json:"message"`
	// Err is the underlying error.
	Err error `json:"-"`
}
