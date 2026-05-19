package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query [cypher]",
	Short: "Run a Cypher query against BloodHound Neo4j",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		query := args[0]
		fmt.Printf("Would run Cypher query against BloodHound:\n  %s\n", query)
		fmt.Println("Neo4j integration coming soon.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(queryCmd)
}
