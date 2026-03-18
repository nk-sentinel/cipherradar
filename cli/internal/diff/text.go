package diff

import (
	"fmt"
	"io"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
)

// FormatText writes a human-readable diff to the writer.
func FormatText(w io.Writer, result *DiffResult) error {
	beforeCount := countComponents(result, true)
	afterCount := countComponents(result, false)

	if _, err := fmt.Fprintln(w, "CipherRadar CBOM Diff"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "====================="); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Before: %s (%d components)\n", result.Before, beforeCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "After:  %s (%d components)\n", result.After, afterCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Added section.
	if _, err := fmt.Fprintf(w, "Added (%d):\n", len(result.Added)); err != nil {
		return err
	}
	if len(result.Added) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
	}
	for _, c := range result.Added {
		loc := firstLocation(&c)
		if _, err := fmt.Fprintf(w, "  + %-20s %s\n", c.Name, loc); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Removed section.
	if _, err := fmt.Fprintf(w, "Removed (%d):\n", len(result.Removed)); err != nil {
		return err
	}
	if len(result.Removed) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
	}
	for _, c := range result.Removed {
		loc := firstLocation(&c)
		if _, err := fmt.Fprintf(w, "  - %-20s %s\n", c.Name, loc); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Changed section.
	if _, err := fmt.Fprintf(w, "Changed (%d):\n", len(result.Changed)); err != nil {
		return err
	}
	if len(result.Changed) == 0 {
		if _, err := fmt.Fprintln(w, "  (none)"); err != nil {
			return err
		}
	}
	for _, cc := range result.Changed {
		loc := firstLocation(&cc.After)
		displayName := cc.Name
		if cc.Before.Name != cc.After.Name {
			displayName = fmt.Sprintf("%s \u2192 %s", cc.Before.Name, cc.After.Name)
		}
		if _, err := fmt.Fprintf(w, "  ~ %-20s %s\n", displayName, loc); err != nil {
			return err
		}
		for _, change := range cc.Changes {
			if _, err := fmt.Fprintf(w, "    %s\n", change); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Unchanged count.
	if _, err := fmt.Fprintf(w, "Unchanged: %d\n", result.Unchanged); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	// Summary line.
	_, err := fmt.Fprintf(w, "Summary: +%d added, -%d removed, ~%d changed, =%d unchanged\n",
		len(result.Added), len(result.Removed), len(result.Changed), result.Unchanged)
	return err
}

// countComponents returns the total number of components for before or after.
func countComponents(result *DiffResult, isBefore bool) int {
	if isBefore {
		return len(result.Removed) + len(result.Changed) + result.Unchanged
	}
	return len(result.Added) + len(result.Changed) + result.Unchanged
}

// firstLocation extracts the first occurrence location from a component, or an empty string.
func firstLocation(c *output.Component) string {
	if c.Evidence != nil && len(c.Evidence.Occurrences) > 0 {
		occ := c.Evidence.Occurrences[0]
		if occ.Line > 0 {
			return fmt.Sprintf("%s:%d", occ.Location, occ.Line)
		}
		return occ.Location
	}
	return ""
}
