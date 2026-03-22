package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/tools"
	"github.com/spf13/cobra"
)

var installToolsCmd = &cobra.Command{
	Use:   "install-tools",
	Short: "Download and install required analysis tools",
	Long: `Download and install external analysis tools required by cradar.

Installs:
  - OpenGrep (taint analysis engine for Pass 2)
  - YARA-X   (binary scanning engine for compiled artifact analysis)

Tools are installed to ~/.cradar/tools/ by default.
Use --tools-dir to override the installation directory.
Use --force to reinstall even if already present.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		toolsDir, _ := cmd.Flags().GetString("tools-dir")
		force, _ := cmd.Flags().GetBool("force")

		// Expand ~ if present.
		if strings.HasPrefix(toolsDir, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("resolving home directory: %w", err)
			}
			toolsDir = filepath.Join(home, toolsDir[2:])
		}

		var hadError bool

		// Install OpenGrep.
		if force || !tools.IsOpenGrepInstalled(toolsDir) {
			if err := tools.InstallOpenGrep(toolsDir); err != nil {
				fmt.Fprintf(os.Stderr, "Error installing OpenGrep: %v\n", err)
				hadError = true
			}
		} else {
			fmt.Printf("OpenGrep already installed at %s/opengrep\n", toolsDir)
		}

		// Install YARA-X.
		if force || !tools.IsYARAXInstalled(toolsDir) {
			if err := tools.InstallYARAX(toolsDir); err != nil {
				fmt.Fprintf(os.Stderr, "Error installing YARA-X: %v\n", err)
				hadError = true
			}
		} else {
			fmt.Printf("YARA-X already installed at %s/yr\n", toolsDir)
		}

		if hadError {
			return fmt.Errorf("one or more tools failed to install")
		}

		fmt.Println("\nAll tools installed successfully.")
		return nil
	},
}

func init() {
	installToolsCmd.Flags().String("tools-dir", tools.DefaultToolsDir(), "directory to install tools into")
	installToolsCmd.Flags().Bool("force", false, "reinstall tools even if already present")

	rootCmd.AddCommand(installToolsCmd)
}
