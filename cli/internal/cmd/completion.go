package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `Generate a shell completion script for cradar.

To load completion for the current session:

  bash:        source <(cradar completion bash)
  zsh:         source <(cradar completion zsh)
  fish:        cradar completion fish | source
  powershell:  cradar completion powershell | Out-String | Invoke-Expression

To install permanently, redirect the output to your shell's completion
directory (e.g. /etc/bash_completion.d, ~/.zfunc, ~/.config/fish/completions).
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		out := cmd.OutOrStdout()
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(out)
		case "zsh":
			return cmd.Root().GenZshCompletion(out)
		case "fish":
			return cmd.Root().GenFishCompletion(out, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(out)
		}
		return fmt.Errorf("unsupported shell: %s", args[0])
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
