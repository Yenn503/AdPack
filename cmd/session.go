package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"adpack/core"
	"adpack/utils"

	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage engagement sessions (save/load/list/delete state)",
	Long:  "Save and restore adpack state across engagements. Sessions persist hosts, users, creds, edges, and phase progress.",
}

var sessionSaveCmd = &cobra.Command{
	Use:   "save <name>",
	Short: "Save current state to a named session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := DB.LoadState()
		if err != nil {
			return fmt.Errorf("load state: %w", err)
		}
		if err := core.SaveSession(args[0], state); err != nil {
			return err
		}
		utils.StepOk(fmt.Sprintf("Session saved: %s", args[0]))
		return nil
	},
}

var sessionLoadCmd = &cobra.Command{
	Use:   "load <name>",
	Short: "Load state from a saved session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		state, err := core.LoadSession(args[0])
		if err != nil {
			return err
		}
		// Health check before loading
		issues := core.ValidateSessionHealth(state)
		if len(issues) > 0 {
			fmt.Println("Session health warnings:")
			for _, issue := range issues {
				fmt.Printf("  - %s\n", issue)
			}
		}
		if err := DB.SaveState(state); err != nil {
			return fmt.Errorf("save state to db: %w", err)
		}
		utils.StepOk(fmt.Sprintf("Session loaded: %s (%d hosts, %d creds, %d edges)",
			args[0], len(state.Hosts), len(state.Creds), len(state.Edges)))
		return nil
	},
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		summaries, err := core.ListSessions()
		if err != nil {
			return err
		}
		if len(summaries) == 0 {
			fmt.Println("No saved sessions.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tDOMAIN\tHOSTS\tCREDS\tEDGES\tPHASE\tTIMESTAMP")
		for _, s := range summaries {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%s\n",
				s.Name, s.Domain, s.Hosts, s.Creds, s.Edges, s.Phase,
				s.Timestamp.Format("2006-01-02 15:04"))
		}
		w.Flush()
		return nil
	},
}

var sessionDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a saved session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := core.DeleteSession(args[0]); err != nil {
			return err
		}
		utils.StepOk(fmt.Sprintf("Session deleted: %s", args[0]))
		return nil
	},
}

var sessionExportPath string

var sessionExportCmd = &cobra.Command{
	Use:   "export <name>",
	Short: "Export a session to a portable JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out := sessionExportPath
		if out == "" {
			out = args[0] + ".export.json"
		}
		if err := core.ExportSession(args[0], out); err != nil {
			return err
		}
		utils.StepOk(fmt.Sprintf("Session exported: %s -> %s", args[0], out))
		return nil
	},
}

var sessionImportCmd = &cobra.Command{
	Use:   "import <name> <file>",
	Short: "Import a session from a portable JSON envelope",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := core.ImportSession(args[0], args[1]); err != nil {
			return err
		}
		utils.StepOk(fmt.Sprintf("Session imported: %s from %s", args[0], args[1]))
		return nil
	},
}

func init() {
	sessionExportCmd.Flags().StringVarP(&sessionExportPath, "output", "o", "", "Output file path (default: <name>.export.json)")
	sessionCmd.AddCommand(sessionSaveCmd, sessionLoadCmd, sessionListCmd, sessionDeleteCmd, sessionExportCmd, sessionImportCmd)
	rootCmd.AddCommand(sessionCmd)
}
