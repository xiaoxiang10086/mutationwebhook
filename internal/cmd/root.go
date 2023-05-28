package cmd

import (
	"github.com/spf13/cobra"
)

// GetRootCommand returns the root cobra command to be executed
// by main.
func GetRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "layoctl",
		Short: "Layotto control interface.",
	}

	cmd.AddCommand(getServerCommand())

	return cmd
}
