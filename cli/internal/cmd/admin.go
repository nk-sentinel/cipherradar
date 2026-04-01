package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrative commands (break-glass recovery)",
}

var adminResetPasswordCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "Reset an admin user's password directly via database (break-glass recovery)",
	Long: `Reset a user's password by connecting directly to the database.

This command is intended for break-glass recovery when the last Org Admin
is locked out and cannot use the web UI. It generates a temporary password,
hashes it with bcrypt, and prints it for the administrator to use.

In a production deployment, the admin would run this on a host with direct
database access and then pipe the SQL output to psql.`,
	RunE: runAdminResetPassword,
}

func init() {
	adminResetPasswordCmd.Flags().String("email", "", "email address of the user to reset (required)")
	adminResetPasswordCmd.Flags().String("database-url", "", "PostgreSQL connection string (default: from CRADAR_DATABASE_URL env)")
	_ = adminResetPasswordCmd.MarkFlagRequired("email")

	adminCmd.AddCommand(adminResetPasswordCmd)
	rootCmd.AddCommand(adminCmd)
}

// generateTempPassword creates a random 24-character hex password.
func generateTempPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func runAdminResetPassword(cmd *cobra.Command, args []string) error {
	email, _ := cmd.Flags().GetString("email")
	if email == "" {
		return fmt.Errorf("--email is required")
	}

	dbURL, _ := cmd.Flags().GetString("database-url")
	if dbURL == "" {
		dbURL = os.Getenv("CRADAR_DATABASE_URL")
	}

	// Generate temporary password
	tempPassword, err := generateTempPassword()
	if err != nil {
		return fmt.Errorf("generating temporary password: %w", err)
	}

	// Hash with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	if dbURL != "" {
		// If database URL is provided, print the SQL to execute
		fmt.Fprintf(cmd.OutOrStdout(), "-- Break-glass password reset for: %s\n", email)
		fmt.Fprintf(cmd.OutOrStdout(), "-- Temporary password: %s\n", tempPassword)
		fmt.Fprintf(cmd.OutOrStdout(), "-- Run the following SQL against your database:\n\n")
		fmt.Fprintf(cmd.OutOrStdout(),
			"UPDATE users SET hashed_password = '%s', disabled_at = NULL, is_active = true, updated_at = now() WHERE email = '%s';\n",
			string(hash), email)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), "-- IMPORTANT: Change this password immediately after login.\n")
	} else {
		// No database URL — just generate and print the password + hash
		fmt.Fprintf(cmd.OutOrStdout(), "Break-glass password reset for: %s\n\n", email)
		fmt.Fprintf(cmd.OutOrStdout(), "Temporary password: %s\n", tempPassword)
		fmt.Fprintf(cmd.OutOrStdout(), "Bcrypt hash:        %s\n\n", string(hash))
		fmt.Fprintln(cmd.OutOrStdout(), "Run the following SQL against your database:")
		fmt.Fprintf(cmd.OutOrStdout(),
			"  UPDATE users SET hashed_password = '%s', disabled_at = NULL, is_active = true, updated_at = now() WHERE email = '%s';\n\n",
			string(hash), email)
		fmt.Fprintln(cmd.OutOrStdout(), "IMPORTANT: Change this password immediately after login.")
	}

	return nil
}
