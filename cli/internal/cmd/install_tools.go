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
	Long: `Download and install external analysis tools required by cbom.

Currently installs:
  - OpenGrep (taint analysis engine for Pass 2)

Tools are installed to ~/.cbom/tools/ by default.
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

		if !force && tools.IsOpenGrepInstalled(toolsDir) {
			fmt.Printf("OpenGrep already installed at %s/opengrep\n", toolsDir)
			fmt.Println("Use --force to reinstall")
			return nil
		}

		return tools.InstallOpenGrep(toolsDir)
	},
}

func init() {
	installToolsCmd.Flags().String("tools-dir", tools.DefaultToolsDir(), "directory to install tools into")
	installToolsCmd.Flags().Bool("force", false, "reinstall tools even if already present")

	rootCmd.AddCommand(installToolsCmd)
}
