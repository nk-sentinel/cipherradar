package scanner

import (
	"os"
	"path/filepath"
	"time"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// ScanDir walks a directory tree, dispatches each file to the appropriate scanner,
// and returns the aggregated scan result.
func ScanDir(root string, registry *Registry, passes []int) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Target:    root,
		StartTime: time.Now(),
		PassesRun: passes,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, types.ScanError{
				File:    path,
				Message: err.Error(),
			})
			return nil // continue walking
		}

		if d.IsDir() {
			// Skip common non-source directories
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" ||
				name == "vendor" || name == ".venv" || name == "venv" ||
				name == "dist" || name == "build" || name == ".idea" || name == ".vscode" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := DetectLanguage(path)
		s := registry.ForExtension(ext)
		if s == nil {
			return nil // no scanner for this file type
		}

		content, err := os.ReadFile(path)
		if err != nil {
			result.Errors = append(result.Errors, types.ScanError{
				File:    path,
				Message: err.Error(),
			})
			return nil
		}

		// Make path relative to root for findings
		relPath, _ := filepath.Rel(root, path)

		findings, err := s.ScanFile(relPath, content)
		if err != nil {
			result.Errors = append(result.Errors, types.ScanError{
				File:    relPath,
				Message: err.Error(),
			})
			return nil
		}

		result.Findings = append(result.Findings, findings...)
		result.FilesScanned++
		return nil
	})

	result.EndTime = time.Now()

	if err != nil {
		return result, err
	}
	return result, nil
}
