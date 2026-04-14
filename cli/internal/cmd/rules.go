package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nk-sentinel/cipherradar/cli/internal/explain"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Inspect the rule corpus (list, explain)",
	Long: `The rules command surfaces metadata about the embedded OpenGrep rule
corpus. Use it to discover which rules cradar ships with, which are opt-in,
and what each rule detects.`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all embedded rules with their lifecycle metadata",
	RunE:  runRulesList,
}

var rulesExplainCmd = &cobra.Command{
	Use:   "explain <rule-id>",
	Short: "Show the metadata and (if seeded) documentation for a rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runRulesExplain,
}

func init() {
	rulesListCmd.Flags().String("format", "table", "output format (table, json)")
	rulesListCmd.Flags().String("category", "", "filter by category (inventory|security)")
	rulesListCmd.Flags().String("maturity", "", "filter by maturity (experimental|stable|deprecated)")
	rulesListCmd.Flags().Bool("only-default-off", false, "only show rules whose default_enabled is false")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesExplainCmd)
	rootCmd.AddCommand(rulesCmd)
}

func runRulesList(cmd *cobra.Command, _ []string) error {
	rs, err := explain.All()
	if err != nil {
		return err
	}

	catFilter, _ := cmd.Flags().GetString("category")
	matFilter, _ := cmd.Flags().GetString("maturity")
	onlyOff, _ := cmd.Flags().GetBool("only-default-off")
	catFilter = strings.ToLower(strings.TrimSpace(catFilter))
	matFilter = strings.ToLower(strings.TrimSpace(matFilter))

	filtered := rs[:0:0]
	for _, r := range rs {
		if catFilter != "" && string(r.Category) != catFilter {
			continue
		}
		if matFilter != "" && string(r.Maturity) != matFilter {
			continue
		}
		if onlyOff && r.DefaultEnabled {
			continue
		}
		filtered = append(filtered, r)
	}

	format, _ := cmd.Flags().GetString("format")
	switch strings.ToLower(format) {
	case "json":
		return writeRulesJSON(cmd.OutOrStdout(), filtered)
	case "table", "":
		return writeRulesTable(cmd.OutOrStdout(), filtered)
	default:
		return fmt.Errorf("unknown --format %q (valid: table, json)", format)
	}
}

func runRulesExplain(cmd *cobra.Command, args []string) error {
	id := args[0]
	r, err := explain.FindByID(id)
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("rule %q not found in embedded corpus (run `cradar rules list` to browse)", id)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Rule:           %s\n", r.ID)
	fmt.Fprintf(out, "Source:         %s\n", r.File)
	fmt.Fprintf(out, "Languages:      %s\n", strings.Join(r.Languages, ", "))
	fmt.Fprintf(out, "Category:       %s\n", r.Category)
	fmt.Fprintf(out, "Maturity:       %s\n", r.Maturity)
	fmt.Fprintf(out, "Noise risk:     %s\n", r.NoiseRisk)
	fmt.Fprintf(out, "Default on:     %t\n", r.DefaultEnabled)
	if r.Severity != "" {
		fmt.Fprintf(out, "Severity:       %s\n", r.Severity)
	}
	if r.Message != "" {
		fmt.Fprintf(out, "\nMessage:\n%s\n", indent(r.Message, "  "))
	}
	if doc := explain.Doc(id); doc != "" {
		fmt.Fprintf(out, "\n--- Guidance ---\n%s", doc)
		if !strings.HasSuffix(doc, "\n") {
			fmt.Fprintln(out)
		}
	}
	return nil
}

func writeRulesTable(w io.Writer, rs []explain.Rule) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tLANG\tCATEGORY\tMATURITY\tDEFAULT\tNOISE\tSEVERITY")
	for _, r := range rs {
		lang := ""
		if len(r.Languages) > 0 {
			lang = r.Languages[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
			r.ID, lang, r.Category, r.Maturity,
			r.DefaultEnabled, r.NoiseRisk, r.Severity)
	}
	fmt.Fprintf(tw, "\n%d rule(s)\n", len(rs))
	return tw.Flush()
}

func writeRulesJSON(w io.Writer, rs []explain.Rule) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rs)
}

// indent prefixes every line of s with pad. Used for pretty-printing the
// multi-line rule message in explain output.
func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + strings.TrimRight(lines[i], "\r")
	}
	return strings.Join(lines, "\n")
}
