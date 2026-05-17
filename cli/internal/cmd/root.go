package cmd

import (
	"fmt"
	"os"

	"github.com/nk-sentinel/cipherradar/cli/internal/output"
	clilog "github.com/nk-sentinel/cipherradar/cli/pkg/log"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:               "cradar",
	Short:             "CipherRadar — cryptographic asset scanner, CBOM generator, and compliance checker",
	Long:              "CipherRadar — cryptographic asset scanner, CBOM generator, and compliance checker",
	PersistentPreRunE: initLogger,
}

func init() {
	rootCmd.PersistentFlags().String("config", ".cradar.yml", "path to configuration file")
	rootCmd.PersistentFlags().Bool("verbose", false, "enable verbose output")
	rootCmd.PersistentFlags().Bool("debug", false, "enable debug-level logs")
	rootCmd.PersistentFlags().Bool("quiet", false, "suppress info output; log errors only")
	rootCmd.PersistentFlags().String("log-file", "", "path to the log file (default: ~/.cradar/logs/cradar-<ts>-<pid>.log.jsonl)")
	rootCmd.PersistentFlags().String("log-format", "json", "log file format (json|text)")
	rootCmd.PersistentFlags().Bool("log-include-source", false, "include matched source snippets in logs (off by default for privacy)")
}

// initLogger is the PersistentPreRunE for rootCmd. It reads the logging
// flags and sets up the global logger. A failure to open the log file
// is reported to stderr but does not abort the command — we fall back to
// a no-op logger so scans still work on read-only filesystems.
func initLogger(cmd *cobra.Command, _ []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	debug, _ := cmd.Flags().GetBool("debug")
	quiet, _ := cmd.Flags().GetBool("quiet")
	logFile, _ := cmd.Flags().GetString("log-file")
	logFormat, _ := cmd.Flags().GetString("log-format")
	includeSource, _ := cmd.Flags().GetBool("log-include-source")

	level := clilog.LevelInfo
	switch {
	case debug:
		level = clilog.LevelDebug
	case verbose:
		level = clilog.LevelVerbose
	case quiet:
		level = clilog.LevelQuiet
	}

	format := clilog.FormatJSON
	if logFormat == "text" {
		format = clilog.FormatText
	}

	_, err := clilog.Init(clilog.Config{
		Level:         level,
		Format:        format,
		LogFile:       logFile,
		IncludeSource: includeSource,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cradar: log init failed: %v (continuing without file logging)\n", err)
		return nil
	}
	return nil
}

// logger returns the active logger (no-op if Init has not run).
func logger() *clilog.Logger { return clilog.Get() }

// Execute runs the root command.
func Execute() error {
	output.AppVersion = Version
	err := rootCmd.Execute()
	if err != nil {
		if lg := clilog.Get(); lg.Path() != "" {
			fmt.Fprintf(os.Stderr, "cradar: see log at %s\n", lg.Path())
		}
	}
	_ = clilog.Get().Close()
	return err
}
