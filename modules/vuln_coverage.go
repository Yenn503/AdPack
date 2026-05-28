package modules

import (
	"fmt"
	"strings"

	"adpack/core"
	"adpack/utils"

	"charm.land/lipgloss/v2"
)

type VulnStatus int

const (
	VulnNotFound VulnStatus = iota
	VulnFound
	VulnExploited
)

type VulnEntry struct {
	Category    string
	Name        string
	Description string
	Status      VulnStatus
	Detail      string
}

func (v VulnEntry) Icon() string {
	switch v.Status {
	case VulnExploited:
		return utils.SuccessStyle.Render("✓")
	case VulnFound:
		return utils.WarningStyle.Render("●")
	default:
		return lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("○")
	}
}

func AssessVulnCoverage(state *core.ADState) []VulnEntry {
	entries := []VulnEntry{}

	// ── Credential Acquisition ──────────────────────────────
	hasASREP := false
	hasKerberoast := false
	hasDescCreds := false
	hasSpray := false
	hasUserPass := false
	hasCrossDomain := false
	for _, c := range state.Creds {
		switch c.Source {
		case "asrep_roast":
			hasASREP = true
		case "kerberoast":
			hasKerberoast = true
		case "description":
			hasDescCreds = true
		case "password_spray":
			hasSpray = true
		case "username_spray":
			hasUserPass = true
		case "cross_domain_reuse":
			hasCrossDomain = true
		}
	}
	for _, u := range state.Users {
		if u.NoPreauth {
			hasASREP = true
		}
		if u.SPNs != "" {
			hasKerberoast = true
		}
	}

	entries = append(entries, VulnEntry{"Credential Acquisition", "AS-REP Roasting", "Users without Kerberos pre-authentication", status(hasASREP), countUsers(state, func(u core.User) bool { return u.NoPreauth })})
	entries = append(entries, VulnEntry{"Credential Acquisition", "Kerberoasting", "Service accounts with SPNs set", status(hasKerberoast), countUsers(state, func(u core.User) bool { return u.SPNs != "" })})
	entries = append(entries, VulnEntry{"Credential Acquisition", "Creds in Descriptions", "Passwords stored in AD user descriptions", status(hasDescCreds), ""})
	entries = append(entries, VulnEntry{"Credential Acquisition", "Password Spray", "Known weak/default credentials tested", status(hasSpray), fmt.Sprintf("%d creds", len(state.Creds))})
	entries = append(entries, VulnEntry{"Credential Acquisition", "Username=Password", "Username as password tested per user", status(hasUserPass), ""})
	entries = append(entries, VulnEntry{"Credential Acquisition", "Cross-Domain Reuse", "Credentials tested across domain trusts", status(hasCrossDomain), ""})

	// ── MSSQL ───────────────────────────────────────────────
	hasMSSQLImpersonate := false
	hasMSSQLSysadmin := false
	hasMSSQLXPCMD := false
	hasMSSQLLinked := false
	hasMSSQLCoerce := false
	hasMSSQLUserImp := false
	for _, e := range state.Edges {
		switch e.AccessRight {
		case "MSSQL_EXECUTE_AS_LOGIN":
			hasMSSQLImpersonate = true
		case "MSSQL_SYSADMIN":
			hasMSSQLSysadmin = true
		case "MSSQL_XP_CMDSHELL":
			hasMSSQLXPCMD = true
		case "MSSQL_LINKED_SERVER":
			hasMSSQLLinked = true
		case "MSSQL_NTLM_COERCE":
			hasMSSQLCoerce = true
		case "MSSQL_EXECUTE_AS_USER":
			hasMSSQLUserImp = true
		}
	}

	entries = append(entries, VulnEntry{"MSSQL", "Login Impersonation", "EXECUTE AS LOGIN privilege chain", status(hasMSSQLImpersonate), edgeCount(state, "MSSQL_EXECUTE_AS_LOGIN")})
	entries = append(entries, VulnEntry{"MSSQL", "Sysadmin Role", "Login has sysadmin server role", status(hasMSSQLSysadmin), edgeCount(state, "MSSQL_SYSADMIN")})
	entries = append(entries, VulnEntry{"MSSQL", "xp_cmdshell", "Command execution via xp_cmdshell → SYSTEM", status(hasMSSQLXPCMD), edgeCount(state, "MSSQL_XP_CMDSHELL")})
	entries = append(entries, VulnEntry{"MSSQL", "Linked Servers", "Cross-server execution via linked SQL instances", status(hasMSSQLLinked), edgeCount(state, "MSSQL_LINKED_SERVER")})
	entries = append(entries, VulnEntry{"MSSQL", "NTLM Coercion", "Force NTLM auth via xp_dirtree/xp_fileexist", status(hasMSSQLCoerce), edgeCount(state, "MSSQL_NTLM_COERCE")})
	entries = append(entries, VulnEntry{"MSSQL", "User Impersonation", "EXECUTE AS USER at database level", status(hasMSSQLUserImp), edgeCount(state, "MSSQL_EXECUTE_AS_USER")})

	// ── ADCS ─────────────────────────────────────────────────
	hasESC1 := false
	hasESC4 := false
	hasESC7 := false
	hasESC8 := false
	hasESC13 := false
	for _, e := range state.Edges {
		switch {
		case strings.Contains(e.AccessRight, "ESC1"):
			hasESC1 = true
		case strings.Contains(e.AccessRight, "ESC4"):
			hasESC4 = true
		case strings.Contains(e.AccessRight, "ESC7"):
			hasESC7 = true
		case strings.Contains(e.AccessRight, "ESC8"):
			hasESC8 = true
		case strings.Contains(e.AccessRight, "ESC13"):
			hasESC13 = true
		}
	}
	if len(state.ADCS) > 0 {
		hasESC8 = true
	}

	entries = append(entries, VulnEntry{"ADCS", "ESC1", "Template allows subject name supply + client auth", status(hasESC1), edgeCount(state, "ADCS_ESC1")})
	entries = append(entries, VulnEntry{"ADCS", "ESC4", "Write access to certificate template ACL", status(hasESC4), edgeCount(state, "ADCS_ESC4")})
	entries = append(entries, VulnEntry{"ADCS", "ESC7", "ManageCA / ManageCertificates permission", status(hasESC7), edgeCount(state, "ADCS_ESC7")})
	entries = append(entries, VulnEntry{"ADCS", "ESC8", "NTLM relay to ADCS HTTP web enrollment", status(hasESC8), fmt.Sprintf("%d templates", len(state.ADCS))})
	entries = append(entries, VulnEntry{"ADCS", "ESC13", "OID group link for enrollment principal", status(hasESC13), edgeCount(state, "ADCS_ESC13")})

	// ── Delegation ──────────────────────────────────────────
	hasUnconstrained := false
	hasConstrained := false
	hasRBCD := false
	for _, e := range state.Edges {
		switch e.AccessRight {
		case "UNCONSTRAINED_DELEGATION":
			hasUnconstrained = true
		case "CONSTRAINED_DELEGATION":
			hasConstrained = true
		case "RBCD":
			hasRBCD = true
		}
	}

	entries = append(entries, VulnEntry{"Delegation", "Unconstrained", "Host trusts any delegation → TGT extraction", status(hasUnconstrained), edgeCount(state, "UNCONSTRAINED_DELEGATION")})
	entries = append(entries, VulnEntry{"Delegation", "Constrained", "Host delegates to specific services", status(hasConstrained), edgeCount(state, "CONSTRAINED_DELEGATION")})
	entries = append(entries, VulnEntry{"Delegation", "RBCD", "Resource-based constrained delegation", status(hasRBCD), edgeCount(state, "RBCD")})

	// ── ACL Abuse ───────────────────────────────────────────
	hasACL := false
	for _, e := range state.Edges {
		switch e.AccessRight {
		case "GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword", "AddMember", "SelfMembership":
			hasACL = true
		}
	}
	entries = append(entries, VulnEntry{"ACL Abuse", "Dangerous ACLs", "GenericAll, WriteDacl, AddMember, ForceChangePassword", status(hasACL), fmt.Sprintf("%d edges", countACLEdges(state))})

	// ── Domain Dominance ────────────────────────────────────
	hasDCSync := false
	hasChildParent := false
	hasDA := false
	for _, e := range state.Edges {
		if e.AccessRight == "DCSYNC" {
			hasDCSync = true
		}
	}
	for _, c := range state.Creds {
		if strings.Contains(strings.ToLower(c.Username), "domain admin") || strings.Contains(strings.ToLower(c.Username), "administrator") {
			hasDA = true
		}
	}
	for _, e := range state.Edges {
		if strings.Contains(e.EdgeType, "child_parent") || strings.Contains(e.AccessRight, "CHILD_PARENT") {
			hasChildParent = true
		}
	}

	entries = append(entries, VulnEntry{"Domain Dominance", "DCSync", "Replicating Directory Changes privilege", status(hasDCSync), edgeCount(state, "DCSYNC")})
	entries = append(entries, VulnEntry{"Domain Dominance", "Child-to-Parent", "Cross-forest escalation via trust", status(hasChildParent), ""})
	entries = append(entries, VulnEntry{"Domain Dominance", "Domain Admin", "DA or equivalent credentials obtained", status(hasDA), adminCredCount(state)})

	// ── Local PrivEsc ───────────────────────────────────────
	hasSYSTEM := false
	hasKrbRelay := false
	for _, e := range state.Edges {
		if strings.Contains(e.TargetPrincipal, "SYSTEM@") {
			hasSYSTEM = true
		}
		if e.AccessRight == "KRB_RELAY_UP" || e.EdgeType == "krb_relay_up" {
			hasKrbRelay = true
		}
	}
	entries = append(entries, VulnEntry{"Local PrivEsc", "SYSTEM Access", "SYSTEM-level access on compromised hosts", status(hasSYSTEM), systemHosts(state)})
	entries = append(entries, VulnEntry{"Local PrivEsc", "KrbRelayUp", "Local SYSTEM via Kerberos relay (no LDAP signing)", status(hasKrbRelay), edgeCount(state, "KRB_RELAY_UP")})

	// ── Persistence ─────────────────────────────────────────
	hasPersistence := state.Phases[core.PhasePersistence] == core.PhaseComplete
	entries = append(entries, VulnEntry{"Persistence", "Backdoors", "Scheduled tasks, AdminSDHolder, Golden Ticket", status(hasPersistence), ""})

	return entries
}

func status(found bool) VulnStatus {
	if found {
		return VulnFound
	}
	return VulnNotFound
}

func countUsers(state *core.ADState, fn func(core.User) bool) string {
	n := 0
	for _, u := range state.Users {
		if fn(u) {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d users", n)
}

func edgeCount(state *core.ADState, accessRight string) string {
	n := 0
	for _, e := range state.Edges {
		if strings.EqualFold(e.AccessRight, accessRight) {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d edges", n)
}

func countACLEdges(state *core.ADState) int {
	n := 0
	for _, e := range state.Edges {
		switch e.AccessRight {
		case "GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword", "AddMember", "SelfMembership":
			n++
		}
	}
	return n
}

func adminCredCount(state *core.ADState) string {
	n := 0
	for _, c := range state.Creds {
		if strings.Contains(strings.ToLower(c.Username), "domain admin") || strings.Contains(strings.ToLower(c.Username), "administrator") {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d creds", n)
}

func systemHosts(state *core.ADState) string {
	hosts := map[string]bool{}
	for _, e := range state.Edges {
		if strings.Contains(e.TargetPrincipal, "SYSTEM@") {
			hosts[e.TargetPrincipal] = true
		}
	}
	if len(hosts) == 0 {
		return ""
	}
	return fmt.Sprintf("%d hosts", len(hosts))
}

func PrintVulnCoverage(entries []VulnEntry) {
	catStyle := lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary)
	nameStyle := lipgloss.NewStyle().Foreground(utils.ColorHighlight)
	descStyle := lipgloss.NewStyle().Foreground(utils.ColorMuted)
	detailStyle := lipgloss.NewStyle().Foreground(utils.ColorSecondary)

	var currentCat string
	for _, e := range entries {
		if e.Category != currentCat {
			currentCat = e.Category
			fmt.Printf("\n  %s\n", catStyle.Render(strings.ToUpper(currentCat)))
		}
		detail := ""
		if e.Detail != "" {
			detail = "  " + detailStyle.Render("["+e.Detail+"]")
		}
		fmt.Printf("    %s  %s  %s%s\n",
			e.Icon(),
			nameStyle.Render(e.Name),
			descStyle.Render(e.Description),
			detail)
	}
}

func PrintLootSummary(state *core.ADState) {
	bar := strings.Repeat("─", 56)

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
	fmt.Printf("  %s\n", lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary).Render("LOOT SUMMARY"))
	fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))

	// Credentials table
	fmt.Printf("\n  %s  %s\n",
		lipgloss.NewStyle().Bold(true).Foreground(utils.ColorWarning).Render("CREDENTIALS"),
		lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(fmt.Sprintf("(%d total, %d validated)", len(state.Creds), countValidated(state.Creds))))

	if len(state.Creds) > 0 {
		for _, c := range state.Creds {
			validIcon := utils.SuccessStyle.Render("✓")
			if !c.Validated {
				validIcon = lipgloss.NewStyle().Foreground(utils.ColorMuted).Render("?")
			}
			secret := c.Secret
			if c.Hash != "" {
				if len(c.Hash) >= 32 {
					secret = c.Hash[:32] + "..."
				} else {
					secret = c.Hash + "..."
				}
			}
			if secret == "" {
				secret = "(empty)"
			}
			fmt.Printf("    %s  %s\\%s  %s  %s\n",
				lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
				c.Domain, c.Username,
				lipgloss.NewStyle().Foreground(utils.ColorWarning).Render(secret),
				validIcon)
		}
	}

	// Hosts
	fmt.Printf("\n  %s  %s\n",
		lipgloss.NewStyle().Bold(true).Foreground(utils.ColorInfo).Render("HOSTS"),
		lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(fmt.Sprintf("(%d total)", len(state.Hosts))))
	for _, h := range state.Hosts {
		dc := ""
		if h.IsDC {
			dc = utils.WarningStyle.Render(" [DC]")
		}
		compromised := ""
		for _, e := range state.Edges {
			if strings.Contains(e.TargetPrincipal, "SYSTEM@"+h.IP) || strings.Contains(e.TargetPrincipal, "SYSTEM@"+h.Hostname) {
				compromised = utils.SuccessStyle.Render(" [COMPROMISED]")
				break
			}
		}
		fmt.Printf("    %s  %s  %s%s%s\n",
			lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
			h.IP,
			lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(h.Hostname),
			dc, compromised)
	}

	// Sessions
	if len(state.Sessions) > 0 {
		realSessions := 0
		for _, s := range state.Sessions {
			if s.Username != "" && s.Host != "" {
				realSessions++
			}
		}
		if realSessions > 0 {
			fmt.Printf("\n  %s  %s\n",
				lipgloss.NewStyle().Bold(true).Foreground(utils.ColorHighlight).Render("SESSIONS"),
				lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(fmt.Sprintf("(%d active)", realSessions)))
			for _, s := range state.Sessions {
				if s.Username == "" || s.Host == "" {
					continue
				}
				src := s.SourceIP
				if src == "" {
					src = "local"
				}
				fmt.Printf("    %s  %s @ %s  (from %s)\n",
					lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
					s.Username, s.Host, src)
			}
		}
	}

	// Privilege Edges
	if len(state.Edges) > 0 {
		fmt.Printf("\n  %s  %s\n",
			lipgloss.NewStyle().Bold(true).Foreground(utils.ColorPrimary).Render("PRIVILEGE EDGES"),
			lipgloss.NewStyle().Foreground(utils.ColorMuted).Render(fmt.Sprintf("(%d total)", len(state.Edges))))
		edgeTypes := map[string]int{}
		for _, e := range state.Edges {
			edgeTypes[e.AccessRight]++
		}
		for right, count := range edgeTypes {
			fmt.Printf("    %s  %s  x%d\n",
				lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("·"),
				right, count)
		}
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(utils.ColorSecondary).Render("  " + bar))
}

func countValidated(creds []core.Credential) int {
	n := 0
	for _, c := range creds {
		if c.Validated {
			n++
		}
	}
	return n
}
