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

type presetDef struct {
	Name        string
	Description string
	Cypher      string
}

var queryPresets = []presetDef{
	{
		"da-sessions", "Users with sessions on Domain Controllers (DA session hunting)",
		"MATCH (u:User)-[:HasSession]->(c:Computer) WHERE c.Domain ENDS WITH '.LOCAL' AND c.Name ENDS WITH '$' RETURN u.Name AS User, c.Name AS Computer",
	},
	{
		"shortest-da", "Shortest paths to Domain Admin from owned principals",
		"MATCH (n {owned:true}), (m:Group {name:'DOMAIN ADMINS@' + n.Domain}) CALL apoc.algo.dijkstra(n, m, 'MemberOf|AdminTo|HasSession|ForceChangePassword|AddMember|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|TrustedBy|HasSIDHistory|Contains', 'weight') YIELD path RETURN path",
	},
	{
		"kerberoastable", "Users with Kerberoastable SPNs",
		"MATCH (u:User {hasspn:true}) RETURN u.Name AS User, u.DisplayName AS Display, u.Domain AS Domain",
	},
	{
		"asrep-roastable", "Users without Kerberos pre-authentication",
		"MATCH (u:User {dontreqpreauth:true}) RETURN u.Name AS User, u.Domain AS Domain",
	},
	{
		"dcsync-rights", "Principals with DCSync rights (DS-Replication-Get-Changes)",
		"MATCH (n)-[:AllExtendedRights|GenericAll]->(dc:Computer) WHERE dc.Domain ENDS WITH '.LOCAL' AND dc.Name ENDS WITH '$' RETURN n.Name AS Principal, dc.Name AS Target ORDER BY n.Name",
	},
	{
		"admin-count", "Users with AdminCount=1 (privileged group members)",
		"MATCH (u:User {admincount:true}) RETURN u.Name AS User, u.Domain AS Domain ORDER BY u.Name",
	},
	{
		"constrained-delegation", "Computers with constrained delegation configured",
		"MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.Name AS Computer, c.AllowedToDelegate AS DelegatedTo ORDER BY c.Name",
	},
	{
		"unconstrained-delegation", "Computers with unconstrained delegation",
		"MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.Name AS Computer, c.OperatingSystem AS OS ORDER BY c.Name",
	},
	{
		"rbcd", "Computers with Resource-Based Constrained Delegation (RBCD)",
		"MATCH (c:Computer)-[:AllowedToActOnBehalfOfOtherIdentity]->(t:Computer) RETURN c.Name AS Source, t.Name AS Target ORDER BY c.Name",
	},
	{
		"gpo-abuse", "GPO abuse paths — principals with write access to GPOs",
		"MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(g:GPO) RETURN n.Name AS Principal, g.Name AS GPO, g.Domain AS Domain ORDER BY n.Name",
	},
	{
		"outbound-trusts", "Outbound trust relationships to other domains",
		"MATCH (d:Domain)-[:TrustedBy]->(t:Domain) RETURN d.Name AS Source, t.Name AS Target, t.TrustType AS TrustType",
	},
	{
		"owned-principals", "All currently owned principals in the graph",
		"MATCH (n {owned:true}) RETURN labels(n)[0] AS Type, n.Name AS Name, n.Domain AS Domain ORDER BY Type, Name",
	},
	{
		"adcs-esc1", "Certificate templates vulnerable to ESC1 (enrollee supplies SAN)",
		"MATCH (ct:CertTemplate)-[:Enroll]->(g:Group) WHERE ct.RequiresManagerApproval = false AND ct.SchemaVersion >= 1 AND ct.EnrolleeSuppliesSubject = true RETURN ct.Name AS Template, g.Name AS EnrollGroup ORDER BY ct.Name",
	},
	{
		"highvalue-targets", "All high-value targets marked by BloodHound",
		"MATCH (n) WHERE n.highvalue = true RETURN labels(n)[0] AS Type, n.Name AS Name ORDER BY Type, n.Name",
	},
}

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
	presetName    string
	listPresets   bool
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

Examples:
  adpack query "MATCH (u:User {name:'KRBTGT@SEVENKINGDOMS.LOCAL'}) RETURN u"
  adpack query --preset da-sessions
  adpack query --list-presets
  adpack query --json "MATCH (n) RETURN count(n) AS total"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runQuery,
}

func runQuery(_ *cobra.Command, args []string) error {
	if listPresets {
		for _, p := range queryPresets {
			fmt.Printf("  %-25s  %s\n", p.Name, p.Description)
		}
		return nil
	}

	query := ""
	if presetName != "" {
		for _, p := range queryPresets {
			if p.Name == presetName {
				query = p.Cypher
				break
			}
		}
		if query == "" {
			return fmt.Errorf("unknown preset %q — use --list-presets to see available presets", presetName)
		}
	} else if len(args) > 0 {
		query = args[0]
	} else {
		return fmt.Errorf("either a raw Cypher query, --preset, or --list-presets is required")
	}

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
	queryCmd.Flags().StringVar(&presetName, "preset", "", "Run a preset Cypher query (see --list-presets)")
	queryCmd.Flags().BoolVar(&listPresets, "list-presets", false, "List available preset queries")
	rootCmd.AddCommand(queryCmd)
}
