package cmd

import (
	"adpack/core"
	"fmt"

	"github.com/spf13/cobra"
)

var reportOutput string

var reportCmd = &cobra.Command{
	Use: "report", Short: "Generate engagement reports",
}

var reportHTMLCmd = &cobra.Command{
	Use: "html", Short: "Generate HTML report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if reportOutput == "" {
			return fmt.Errorf("--output is required")
		}
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		data := core.GenerateReportData(state)
		return core.GenerateHTMLReport(data, reportOutput)
	},
}

var reportMDCmd = &cobra.Command{
	Use: "md", Short: "Generate Markdown report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if reportOutput == "" {
			return fmt.Errorf("--output is required")
		}
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		data := core.GenerateReportData(state)
		return core.GenerateMDReport(data, reportOutput)
	},
}

var reportJSONCmd = &cobra.Command{
	Use: "json", Short: "Generate JSON report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if reportOutput == "" {
			return fmt.Errorf("--output is required")
		}
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		data := core.GenerateReportData(state)
		return core.GenerateJSONReport(data, reportOutput)
	},
}

func init() {
	for _, c := range []*cobra.Command{reportHTMLCmd, reportMDCmd, reportJSONCmd} {
		c.Flags().StringVar(&reportOutput, "output", "", "Output file path")
	}
	reportCmd.AddCommand(reportHTMLCmd, reportMDCmd, reportJSONCmd)
	rootCmd.AddCommand(reportCmd)
}
