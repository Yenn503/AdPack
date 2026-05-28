package core

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

type ReportFinding struct {
	Severity string
	Title    string
	MITRE    string
	Detail   string
}

type ReportData struct {
	Title       string
	GeneratedAt string
	Domain      string
	HostCount   int
	UserCount   int
	CredCount   int
	EdgeCount   int
	Findings    []ReportFinding
	Creds       []Credential
	Hosts       []Host
	Phases      map[Phase]PhaseStatus
}

func GenerateReportData(state *ADState) *ReportData {
	domain := ""
	if len(state.Hosts) > 0 {
		domain = state.Hosts[0].Domain
	}
	return &ReportData{
		Title:       "adpack Engagement Report",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Domain:      domain,
		HostCount:   len(state.Hosts),
		UserCount:   len(state.Users),
		CredCount:   len(state.Creds),
		EdgeCount:   len(state.Edges),
		Findings:    buildFindings(state),
		Creds:       state.Creds,
		Hosts:       state.Hosts,
		Phases:      state.Phases,
	}
}

func buildFindings(state *ADState) []ReportFinding {
	var f []ReportFinding
	hasDA := false
	for _, c := range state.Creds {
		if c.Validated && strings.Contains(c.Username, "Administrator") {
			hasDA = true
			break
		}
	}
	if hasDA {
		f = append(f, ReportFinding{Severity: "Critical", Title: "Domain Admin Access", MITRE: "T1078", Detail: "Valid Domain Admin credentials obtained"})
	}
	for _, e := range state.Edges {
		switch e.AccessRight {
		case "DCSync":
			f = append(f, ReportFinding{Severity: "Critical", Title: "DCSync Privilege", MITRE: "T1003.006", Detail: fmt.Sprintf("%s → DCSync → %s", e.SourcePrincipal, e.TargetPrincipal)})
		case "GenericAll":
			f = append(f, ReportFinding{Severity: "High", Title: "GenericAll ACL", MITRE: "T1098", Detail: fmt.Sprintf("%s has GenericAll on %s", e.SourcePrincipal, e.TargetPrincipal)})
		case "WriteDacl":
			f = append(f, ReportFinding{Severity: "High", Title: "WriteDacl ACL", MITRE: "T1098", Detail: fmt.Sprintf("%s can modify DACL on %s", e.SourcePrincipal, e.TargetPrincipal)})
		}
	}
	return f
}

func GenerateHTMLReport(data *ReportData, output string) error {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{"lower": lower}).Parse(htmlTemplate))
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

func GenerateMDReport(data *ReportData, output string) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s\n\n", data.Title))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", data.GeneratedAt))
	sb.WriteString(fmt.Sprintf("**Domain:** %s  \n", data.Domain))
	sb.WriteString(fmt.Sprintf("**Hosts:** %d | **Users:** %d | **Credentials:** %d | **Edges:** %d\n\n", data.HostCount, data.UserCount, data.CredCount, data.EdgeCount))
	sb.WriteString("## Findings\n\n")
	sb.WriteString("| Severity | Title | MITRE ID | Detail |\n|---|---|---|---|\n")
	for _, f := range data.Findings {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", f.Severity, f.Title, f.MITRE, f.Detail))
	}
	sb.WriteString("\n## Credentials\n\n")
	for _, c := range data.Creds {
		sb.WriteString(fmt.Sprintf("- `%s\\%s` (%s) %s\n", c.Domain, c.Username, c.Type, c.Source))
	}
	return os.WriteFile(output, []byte(sb.String()), 0644)
}

func GenerateJSONReport(data *ReportData, output string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

const htmlTemplate = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:0 auto;padding:20px;background:#0d1117;color:#c9d1d9}
h1{color:#58a6ff}h2{color:#f0883e;border-bottom:1px solid #30363d;padding-bottom:4px}
table{width:100%;border-collapse:collapse;margin:10px 0}
th{background:#161b22;text-align:left;padding:8px}td{padding:8px;border-bottom:1px solid #30363d}
.critical{color:#f85149}.high{color:#f0883e}.medium{color:#d29922}.low{color:#58a6ff}
</style></head><body>
<h1>{{.Title}}</h1>
<p><strong>Generated:</strong> {{.GeneratedAt}} | <strong>Domain:</strong> {{.Domain}} | Hosts: {{.HostCount}} | Users: {{.UserCount}} | Creds: {{.CredCount}} | Edges: {{.EdgeCount}}</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>MITRE ID</th><th>Detail</th></tr>
{{range .Findings}}<tr><td class="{{.Severity | lower}}">{{.Severity}}</td><td>{{.Title}}</td><td>{{.MITRE}}</td><td>{{.Detail}}</td></tr>{{end}}</table>
<h2>Credentials</h2>
<ul>{{range .Creds}}<li><code>{{.Domain}}\{{.Username}}</code> ({{.Type}}) — {{.Source}}</li>{{end}}</ul>
</body></html>`

func lower(s string) string { return strings.ToLower(s) }
