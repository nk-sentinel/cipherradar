package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check <cbom.json>",
	Short: "Check a CBOM against a policy file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("policy check not yet implemented")
		return nil
	},
}

func init() {
	policyCheckCmd.Flags().StringP("policy", "p", "policy.cbom.yml", "path to policy file")
	policyCheckCmd.Flags().String("fail-on", "critical", "minimum severity that causes a non-zero exit")

	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}
