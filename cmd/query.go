package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/spf13/cobra"
)

// Connection settings. Flags override env vars; env vars override defaults.
// BloodHound Community Edition ships with neo4j/bloodhoundcommunityedition
// as default; the AD‑Pentesting‑Notes lab uses neo4j/bloodhound.
var (
	neo4jURI      string
	neo4jUser     string
	neo4jPassword string
	queryDB       string
	queryTimeout  time.Duration
	queryJSON     bool
)

const (
	defaultNeo4jURI      = "bolt://localhost:7687"
	defaultNeo4jUser     = "neo4j"
	defaultNeo4jPassword = "bloodhound"
)

var queryCmd = &cobra.Command{
	Use:   "query [cypher]",
	Short: "Run a Cypher query against the BloodHound Neo4j database",
	Long: `Execute a raw Cypher query against the Neo4j graph database backing
BloodHound and print the result rows.

Connection settings resolve in this order:
  1. CLI flags (--uri, --user, --password)
  2. Environment (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
  3. Defaults (bolt://localhost:7687, neo4j/bloodhound)

Example:
  adpack query "MATCH (u:User {name:'KRBTGT@SEVENKINGDOMS.LOCAL'}) RETURN u"
  adpack query --json "MATCH (n) RETURN count(n) AS total"`,
	Args: cobra.MinimumNArgs(1),
	RunE: runQuery,
}

func runQuery(_ *cobra.Command, args []string) error {
	query := strings.Join(args, " ")

	uri := resolveConn(neo4jURI, "NEO4J_URI", defaultNeo4jURI)
	user := resolveConn(neo4jUser, "NEO4J_USER", defaultNeo4jUser)
	pass := resolveConn(neo4jPassword, "NEO4J_PASSWORD", defaultNeo4jPassword)

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return fmt.Errorf("create driver: %w", err)
	}
	defer driver.Close(ctx)

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("verify connectivity to %s as %s: %w", uri, user, err)
	}

	cfgOpts := []neo4j.ExecuteQueryConfigurationOption{
		neo4j.ExecuteQueryWithReadersRouting(),
	}
	if queryDB != "" {
		cfgOpts = append(cfgOpts, neo4j.ExecuteQueryWithDatabase(queryDB))
	}

	result, err := neo4j.ExecuteQuery(
		ctx, driver, query, nil,
		neo4j.EagerResultTransformer,
		cfgOpts...,
	)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
	}

	if queryJSON {
		return printJSON(result)
	}
	return printTable(result)
}

// resolveConn returns the first non-empty value of flag, env var, default.
func resolveConn(flag, envKey, def string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}

// printTable renders the EagerResult as a lipgloss table. Each record's
// Values() is rendered with formatCellValue so nested maps (typical for
// Neo4j Node values) display key=value pairs rather than %v garbage.
func printTable(r *neo4j.EagerResult) error {
	if r == nil || len(r.Records) == 0 {
		fmt.Println("(0 rows)")
		return nil
	}
	header := r.Keys
	rows := make([][]string, 0, len(r.Records))
	for _, rec := range r.Records {
		vals := rec.Values
		row := make([]string, len(header))
		for i := range header {
			if i < len(vals) {
				row[i] = formatCellValue(vals[i])
			}
		}
		rows = append(rows, row)
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("240"))).
		Headers(header...).
		Rows(rows...)
	fmt.Println(t.Render())
	fmt.Printf("(%d row%s) — %s\n",
		len(r.Records), pluralS(len(r.Records)), summaryStr(r.Summary))
	return nil
}

// printJSON marshals the result as JSON suitable for piping into jq.
func printJSON(r *neo4j.EagerResult) error {
	if r == nil {
		fmt.Println("[]")
		return nil
	}
	out := make([]map[string]any, 0, len(r.Records))
	for _, rec := range r.Records {
		obj := make(map[string]any, len(r.Keys))
		for i, k := range r.Keys {
			if i < len(rec.Values) {
				obj[k] = neoValueToAny(rec.Values[i])
			}
		}
		out = append(out, obj)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// formatCellValue renders Neo4j primitives, nodes, relationships, and paths
// in a human-readable single-line form for tables.
func formatCellValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case neo4j.Node:
		return formatNode(x)
	case neo4j.Relationship:
		return formatRelationship(x)
	case neo4j.Path:
		return formatPath(x)
	case []any:
		parts := make([]string, len(x))
		for i, el := range x {
			parts[i] = formatCellValue(el)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		return formatProps(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func formatNode(n neo4j.Node) string {
	label := strings.Join(n.Labels, ":")
	props := formatProps(n.Props)
	if label == "" {
		return "(" + props + ")"
	}
	return "(:" + label + " " + props + ")"
}

func formatRelationship(r neo4j.Relationship) string {
	return "[:" + r.Type + " " + formatProps(r.Props) + "]"
}

func formatPath(p neo4j.Path) string {
	parts := make([]string, 0, len(p.Nodes)+len(p.Relationships))
	for i, n := range p.Nodes {
		parts = append(parts, formatNode(n))
		if i < len(p.Relationships) {
			parts = append(parts, "-"+formatRelationship(p.Relationships[i])+"->")
		}
	}
	return strings.Join(parts, " ")
}

func formatProps(props map[string]any) string {
	if len(props) == 0 {
		return "{}"
	}
	parts := make([]string, 0, len(props))
	for k, v := range props {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// neoValueToAny converts driver types to plain JSON-marshalable values.
// Avoids leaking driver-specific types into the JSON output.
func neoValueToAny(v any) any {
	switch x := v.(type) {
	case neo4j.Node:
		return map[string]any{
			"_type":  "node",
			"id":     x.ElementId,
			"labels": x.Labels,
			"props":  x.Props,
		}
	case neo4j.Relationship:
		return map[string]any{
			"_type": "relationship",
			"id":    x.ElementId,
			"type":  x.Type,
			"start": x.StartElementId,
			"end":   x.EndElementId,
			"props": x.Props,
		}
	case neo4j.Path:
		nodes := make([]any, len(x.Nodes))
		for i, n := range x.Nodes {
			nodes[i] = neoValueToAny(n)
		}
		rels := make([]any, len(x.Relationships))
		for i, r := range x.Relationships {
			rels[i] = neoValueToAny(r)
		}
		return map[string]any{
			"_type":         "path",
			"nodes":         nodes,
			"relationships": rels,
		}
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[i] = neoValueToAny(el)
		}
		return out
	default:
		return v
	}
}

func summaryStr(s neo4j.ResultSummary) string {
	if s == nil {
		return "summary unavailable"
	}
	return fmt.Sprintf("server=%s db=%s result_time=%s",
		s.Server().Address(),
		s.Database().Name(),
		s.ResultAvailableAfter())
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func init() {
	queryCmd.Flags().StringVar(&neo4jURI, "uri", "", "Neo4j bolt URI (default: $NEO4J_URI or "+defaultNeo4jURI+")")
	queryCmd.Flags().StringVar(&neo4jUser, "user", "", "Neo4j username (default: $NEO4J_USER or "+defaultNeo4jUser+")")
	queryCmd.Flags().StringVar(&neo4jPassword, "password", "", "Neo4j password (default: $NEO4J_PASSWORD or "+defaultNeo4jPassword+")")
	queryCmd.Flags().StringVar(&queryDB, "database", "", "Neo4j database name (default: server default)")
	queryCmd.Flags().DurationVar(&queryTimeout, "timeout", 60*time.Second, "Query timeout")
	queryCmd.Flags().BoolVar(&queryJSON, "json", false, "Emit JSON instead of a rendered table")
	rootCmd.AddCommand(queryCmd)
}
