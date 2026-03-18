package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var installToolsCmd = &cobra.Command{
	Use:   "install-tools",
	Short: "Download and install required analysis tools",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("install-tools not yet implemented")
		return nil
	},
}

func init() {
	installToolsCmd.Flags().String("tools-dir", "~/.cbom/tools/", "directory to install tools into")

	rootCmd.AddCommand(installToolsCmd)
}
