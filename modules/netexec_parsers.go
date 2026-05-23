package modules

import (
	"regexp"
	"strconv"
	"strings"

	"adpack/core"
)

// Parse LDIF output from ldapsearch (ldif-wrap=no). Entries are blank-line
// delimited with "key: value" fields. Extracts cn (={GUID}) and displayName
// from each groupPolicyContainer entry.
func parseLDAPGPOs(output, domain string) []core.GPO {
	var gpos []core.GPO
	seen := make(map[string]struct{})

	for _, block := range strings.Split(output, "\n\n") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}

		var guid, displayName string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, ": ") {
				continue
			}
			key, val, _ := strings.Cut(line, ": ")
			switch key {
			case "cn":
				if m := GPOGUIDRe.FindString(val); m != "" {
					guid = m
				}
			case "displayName":
				displayName = val
			}
		}
		if guid == "" {
			continue
		}
		if _, ok := seen[guid]; ok {
			continue
		}
		seen[guid] = struct{}{}

		gpos = append(gpos, core.GPO{
			Name: displayName, GUID: guid, Domain: domain,
		})
	}
	return gpos
}

var (
	fromRe = regexp.MustCompile(`(?i)\(from ([^)]+)\)`)
)

func parseComputers(output, domain string) []core.Computer {
	var computers []core.Computer
	seen := make(map[string]struct{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if IsNoiseLine(line) {
			continue
		}

		var name, computerDomain string

		// Stage 1: try fully-qualified DOMAIN\COMPUTER$
		m := DomainUserRe.FindStringSubmatch(line)
		if m != nil && strings.HasSuffix(m[2], "$") {
			name = strings.TrimSuffix(m[2], "$")
			computerDomain = m[1]
		} else {
			// Stage 2: try bare COMPUTER$ (domain prefix absent).
			// Match only on whitespace-delimited tokens to avoid false
			// positives from $PATH, error strings, or embedded shell output.
			for _, tok := range strings.Fields(line) {
				if m2 := ComputerBareRe.FindStringSubmatch(tok); m2 != nil {
					name = m2[1]
					computerDomain = domain
					break
				}
			}
		}

		if name == "" || computerDomain == "" {
			continue
		}

		fullName := name + "@" + computerDomain
		if _, ok := seen[fullName]; ok {
			continue
		}
		seen[fullName] = struct{}{}

		lower := strings.ToLower(line)
		isDC := strings.Contains(lower, "windows server") ||
			strings.Contains(lower, "domain controller")

		osInfo := ""
		if idx := strings.Index(lower, "windows server"); idx >= 0 {
			end := idx + 30
			if end > len(line) {
				end = len(line)
			}
			osInfo = strings.TrimSpace(line[idx:end])
		}

		computers = append(computers, core.Computer{
			Name: name, Domain: computerDomain,
			OperatingSystem: osInfo,
			IsDC:            isDC,
		})
	}
	return computers
}

func parseGPOs(output, domain string) []core.GPO {
	var gpos []core.GPO
	seen := make(map[string]struct{})
	lines := strings.Split(output, "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if IsNoiseLine(line) {
			continue
		}

		var name string
		var guid string

		loc := GPOGUIDRe.FindStringIndex(line)
		if loc != nil {
			guid = line[loc[0]:loc[1]]
			name = strings.TrimPrefix(line[:loc[0]], "GPO: ")
			name = strings.TrimSpace(name)
		} else if strings.HasPrefix(line, "GPO:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "GPO:"))
			if i+1 < len(lines) {
				nextLine := strings.TrimSpace(lines[i+1])
				if m := GPOGUIDRe.FindString(nextLine); m != "" {
					guid = m
					i++
				}
			}
		}

		if name == "" || guid == "" {
			continue
		}

		key := guid + "@" + domain
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		gpos = append(gpos, core.GPO{
			Name: name, GUID: guid, Domain: domain,
		})
	}
	return gpos
}

// certipyLineRe matches a data line from nxc ldap -M certipy-find output,
// capturing everything after the module prefix (MODULE IP PORT TARGET).
var certipyLineRe = regexp.MustCompile(`^CERTIPY-\.\.\.\s+\S+\s+\d+\s+\S+\s+(.+)`)

// adcsTemplateBuilder accumulates properties for one ADCS template block.
type adcsTemplateBuilder struct {
	props      map[string]string // key → first value
	ekus       []string          // Extended Key Usage values
	enroll     []string          // Enrollment Rights (principals who can enroll)
	objControl []string          // Object Control principals (write/FullControl — ESC4 relevant)
	vulns      []string          // [!] Vulnerabilities found by certipy
	flags      []string          // Certificate Name Flag values
	lastKey    string            // last property key set (for continuation routing)
}

func newADCSBuilder() *adcsTemplateBuilder {
	return &adcsTemplateBuilder{props: make(map[string]string)}
}

func (b *adcsTemplateBuilder) set(key, val string) {
	b.props[key] = val
	b.lastKey = key
}

func (b *adcsTemplateBuilder) addContinuation(text string) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return
	}
	switch b.lastKey {
	case "Extended Key Usage":
		b.ekus = append(b.ekus, trimmed)
	case "Certificate Name Flag":
		b.flags = append(b.flags, trimmed)
	}
}

func (b *adcsTemplateBuilder) build(domain, caName string) core.ADCSTemplate {
	t := core.ADCSTemplate{
		Name:                    b.props["Template Name"],
		DisplayName:             b.props["Display Name"],
		Domain:                  domain,
		CA:                      caName,
		Enabled:                 parseBoolValue(b.props["Enabled"]),
		ClientAuth:              parseBoolValue(b.props["Client Authentication"]),
		EnrolleeSuppliesSubject: parseBoolValue(b.props["Enrollee Supplies Subject"]),
		RequiresManagerApproval: parseBoolValue(b.props["Requires Manager Approval"]),
		AuthorizedSignatures:    parseIntValue(b.props["Authorized Signatures Required"]),
		SchemaVersion:           parseIntValue(b.props["Schema Version"]),
		EKUs:                    b.ekus,
		Enrollee:                strings.Join(b.enroll, "; "),
	}

	// Classify ESC vulnerabilities from certipy's [!] markers.
	for _, v := range b.vulns {
		parts := strings.SplitN(v, ":", 2)
		escType := strings.TrimSpace(parts[0])
		// Only emit actual ESC# entries (e.g. ESC1, ESC4), not remark-style
		// descriptions like "ESC2 Target Template" or "ESC3 Target Template".
		if !isEscVuln(escType) {
			continue
		}
		if t.Vuln != "" {
			t.Vuln += ","
		}
		t.Vuln += escType
	}

	// Also classify ESC1/ESC13 from template properties for tool independence.
	if t.ClientAuth && t.EnrolleeSuppliesSubject && !t.RequiresManagerApproval && t.AuthorizedSignatures == 0 {
		if !strings.Contains(t.Vuln, "ESC1") {
			if t.Vuln != "" {
				t.Vuln += ","
			}
			t.Vuln += "ESC1"
		}
	}
	if t.ClientAuth && !t.EnrolleeSuppliesSubject && !t.RequiresManagerApproval && t.AuthorizedSignatures == 0 {
		if !strings.Contains(t.Vuln, "ESC13") {
			if t.Vuln != "" {
				t.Vuln += ","
			}
			t.Vuln += "ESC13"
		}
	}

	return t
}

// isEscVuln returns true for canonical ESC# vulnerability identifiers
// (ESC1-ESC16). Filters out remark-style descriptions like "ESC2 Target Template".
func isEscVuln(s string) bool {
	if !strings.HasPrefix(s, "ESC") {
		return false
	}
	rest := strings.TrimPrefix(s, "ESC")
	n, err := strconv.Atoi(rest)
	if err != nil {
		return false
	}
	return n >= 1 && n <= 16
}

// parseBoolValue parses "True"/"False" strings from certipy output.
func parseBoolValue(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "True")
}

// parseIntValue parses integer values from certipy output.
func parseIntValue(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// parseCertipyFind parses the structured text output from nxc ldap -M certipy-find
// into ADCSTemplate values. The output uses consistent indentation to represent
// hierarchy: section headers (no indent), item numbers (mid indent), properties
// (deeper indent), continuations (deepest indent).
func parseCertipyFind(output, domain string) []core.ADCSTemplate {
	var templates []core.ADCSTemplate
	lines := strings.Split(output, "\n")

	inTemplates := false
	inRemarks := false
	var current *adcsTemplateBuilder

	for _, line := range lines {
		content := extractCertipyContent(line)
		if content == "" {
			continue
		}
		trimmed := strings.TrimSpace(content)
		if trimmed == "" {
			continue
		}

		// Section headers
		if trimmed == "Certificate Templates" {
			inTemplates = true
			continue
		}
		if trimmed == "Certificate Authorities" {
			inTemplates = false
			continue
		}
		if !inTemplates {
			continue
		}

		// Template number line — just an integer at mid-indentation.
		if isNumberOnly(trimmed) {
			if current != nil {
				templates = append(templates, current.build(domain, ""))
			}
			current = newADCSBuilder()
			inRemarks = false
			continue
		}

		if current == nil {
			continue
		}

		// Section markers inside a template block
		if strings.HasPrefix(trimmed, "[*]") {
			inRemarks = true
			continue
		}
		if strings.HasPrefix(trimmed, "[!]") {
			inRemarks = false
			vulnText := strings.TrimPrefix(trimmed, "[!]")
			vulnText = strings.TrimSpace(vulnText)
			if !strings.EqualFold(vulnText, "Vulnerabilities") {
				current.vulns = append(current.vulns, vulnText)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "[+]") {
			inRemarks = false
			continue
		}
		if strings.HasPrefix(trimmed, "Permissions") {
			inRemarks = false
			continue
		}

		// Skip everything inside [*] Remarks section
		if inRemarks {
			continue
		}

		// Property line: "Key : Value" or "Key  : Value"
		if idx := strings.Index(trimmed, ":"); idx >= 0 {
			key := strings.TrimSpace(trimmed[:idx])
			val := strings.TrimSpace(trimmed[idx+1:])

			switch {
			case key == "Extended Key Usage":
				current.set(key, val)
				if val != "" {
					current.ekus = append(current.ekus, val)
				}
			case key == "Certificate Name Flag":
				current.set(key, val)
				if val != "" {
					current.flags = append(current.flags, val)
				}
			case key == "Enrollment Rights":
				if val != "" {
					current.enroll = append(current.enroll, val)
				}
			case key == "Full Control Principals", key == "Write Owner Principals",
				key == "Write Dacl Principals", key == "Write Property Enroll",
				key == "Write Property AutoEnroll", key == "Owner":
				if val != "" {
					current.objControl = append(current.objControl, val)
				}
			case strings.HasPrefix(key, "ESC"):
				current.vulns = append(current.vulns, trimmed)
			default:
				current.set(key, val)
			}
		} else if trimmed != "" {
			// Continuation line (additional EKU, cert name flag)
			current.addContinuation(trimmed)
		}
	}

	if current != nil {
		templates = append(templates, current.build(domain, ""))
	}

	return templates
}

// extractCertipyContent strips the nxc module prefix from a certipy-find line,
// returning the indent-preserving content portion. Returns "" for non-data lines.
func extractCertipyContent(line string) string {
	m := certipyLineRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// isNumberOnly returns true if s contains only digits (and optional whitespace).
func isNumberOnly(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// adcsEdgeSet creates PrivilegeEdges from a parsed ADCSTemplate.
// One edge per ESC vulnerability per unique enrollment principal.
func adcsEdgeSet(t core.ADCSTemplate, domain, caHost string, caWeb bool) []core.PrivilegeEdge {
	if !t.Enabled || t.Vuln == "" {
		return nil
	}

	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)
	vulns := strings.Split(t.Vuln, ",")

	for _, v := range vulns {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		prof := rightProfileFor("ADCS_" + v)
		for _, enrollee := range parseEnrollmentPrincipals(t.Enrollee) {
			enrolleeClean := cleanPrincipal(enrollee)
			if enrolleeClean == "" || isHighPrivGroup(enrolleeClean) {
				continue
			}

			tgt := domain + "\\Domain Admins"
			key := enrolleeClean + "|" + tgt + "|" + v
			if seen[key] {
				continue
			}
			seen[key] = true

			preconds := []core.ExecutionPrecondition{
				{
					Kind:        core.PrecondPortOpen,
					Target:      caHost,
					Port:        389,
					Description: "LDAP port for cert template enumeration",
				},
			}

			edges = append(edges, core.PrivilegeEdge{
				SourcePrincipal: enrolleeClean,
				TargetPrincipal: tgt,
				AccessRight:     "ADCS_" + v,
				EdgeType:        "adcs",
				Domain:          domain,
				Source:          "certipy-find",
				Confidence:      0.85,
				Weight:          prof.Weight,
				Exploitability:  prof.Exploitability,
				Noise:           prof.Noise,
				Requires:        prof.Requires,
				Preconditions:   preconds,
			})
		}
	}
	return edges
}

// parseEnrollmentPrincipals parses the semicolon-separated enrollment rights field.
func parseEnrollmentPrincipals(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isHighPrivGroup returns true for built-in high-privilege groups we
// should not use as edge sources (edges from DA→DA are uninteresting).
func isHighPrivGroup(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "domain admins") ||
		strings.Contains(lower, "enterprise admins") ||
		strings.Contains(lower, "administrators") ||
		strings.Contains(lower, "domain controllers") ||
		strings.Contains(lower, "account operators") ||
		strings.Contains(lower, "server operators") ||
		strings.Contains(lower, "backup operators")
}

func parseEnumAV(output string) map[string]string {
	av := make(map[string]string)
	lines := strings.Split(output, "\n")
	inResults := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Found the following AV products") ||
			strings.Contains(line, "AV products found") {
			inResults = true
			continue
		}
		if inResults {
			if strings.HasPrefix(line, "SMB") || strings.HasPrefix(line, "[*]") {
				name := strings.TrimSpace(line)
				if name != "" {
					av[name] = "detected"
				}
			}
		}
	}
	return av
}

// trusteeRe extracts the principal name from "username (S-1-5-21-...)" format.
var trusteeRe = regexp.MustCompile(`^(.+?)\s+\(S-1-`)

// parseDaclReadACEs parses the structured ACE output from nxc ldap -M daclread.
// Each ACE block is delimited by an "ACE[N] info" header with indented fields.
func parseDaclReadACEs(output, domain, targetName string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)

	lines := strings.Split(output, "\n")
	var currentACE struct {
		aceType    string
		accessMask string
		objectType string
		trustee    string
		inBlock    bool
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if currentACE.inBlock {
				// End of current ACE block — emit edge
				e := aceToEdge(currentACE, domain, targetName)
				if e != nil {
					key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
					if !seen[key] {
						seen[key] = true
						edges = append(edges, *e)
					}
				}
				currentACE = struct {
					aceType    string
					accessMask string
					objectType string
					trustee    string
					inBlock    bool
				}{}
			}
			continue
		}

		if strings.Contains(line, "ACE[") && strings.Contains(line, "info") {
			if currentACE.inBlock {
				e := aceToEdge(currentACE, domain, targetName)
				if e != nil {
					key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
					if !seen[key] {
						seen[key] = true
						edges = append(edges, *e)
					}
				}
			}
			currentACE = struct {
				aceType    string
				accessMask string
				objectType string
				trustee    string
				inBlock    bool
			}{inBlock: true}
			continue
		}

		if !currentACE.inBlock {
			continue
		}

		// Strip the nxc prefix: DACLREAD  IP  PORT  HOSTNAME  content
		if idx := strings.Index(line, "ACE Type"); idx >= 0 {
			val := extractACEValue(line)
			currentACE.aceType = val
		} else if strings.Contains(line, "Access mask") {
			currentACE.accessMask = extractACEValue(line)
		} else if strings.Contains(line, "Object type") {
			val := extractACEValue(line)
			// val may be "User-Force-Change-Password (00299570-...)"
			// Extract the name part (before the GUID)
			if idx := strings.Index(val, "("); idx >= 0 {
				currentACE.objectType = strings.TrimSpace(val[:idx])
			} else {
				currentACE.objectType = val
			}
		} else if strings.Contains(line, "Trustee") {
			val := extractACEValue(line)
			if m := trusteeRe.FindStringSubmatch(val); len(m) > 1 {
				currentACE.trustee = strings.TrimSpace(m[1])
			} else {
				currentACE.trustee = val
			}
		}
	}

	// Flush last ACE block
	if currentACE.inBlock {
		e := aceToEdge(currentACE, domain, targetName)
		if e != nil {
			key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
			if !seen[key] {
				edges = append(edges, *e)
			}
		}
	}

	return edges
}

// extractACEValue pulls the value after ": " separator in daclread output fields.
func extractACEValue(line string) string {
	if idx := strings.Index(line, ":"); idx >= 0 {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// rightProfile holds semantic weighting for a privilege edge right.
type rightProfile struct {
	Weight         float64
	Exploitability float64
	Noise          float64
	Requires       []string
}

// edgeWeight maps access rights to their exploitability profiles.
// Lower weight = shorter path cost; higher exploitability = easier to abuse.
var edgeWeight = map[string]rightProfile{
	"GenericAll":               {6, 1.0, 0.7, []string{"nxc"}},
	"WriteDacl":                {7, 0.8, 0.7, []string{"nxc"}},
	"WriteOwner":               {7, 0.8, 0.6, []string{"nxc"}},
	"WriteProperty":            {8, 0.6, 0.5, nil},
	"ForceChangePassword":      {5, 1.0, 0.9, []string{"nxc"}},
	"SelfMembership":           {6, 1.0, 0.8, []string{"nxc"}},
	"AddMember":                {6, 1.0, 0.8, []string{"nxc"}},
	"DCSync":                   {3, 0.95, 1.0, []string{"impacket-secretsdump"}},
	"AllowedToAuthenticate":    {5, 0.8, 0.6, []string{"nxc"}},
	"UserAccountRestrictions":  {8, 0.3, 0.3, nil},
	"MSSQL_EXECUTE_AS_LOGIN":   {5, 0.9, 0.4, []string{"nxc", "mssql"}},
	"MSSQL_SYSADMIN":           {2, 1.0, 0.5, []string{"nxc", "mssql"}},
	"MSSQL_XP_CMDSHELL":        {2, 1.0, 0.6, []string{"nxc", "mssql"}},
	"ADCS_ESC1":                {3, 0.9, 0.3, []string{"certipy"}},
	"ADCS_ESC2":                {4, 0.8, 0.4, []string{"certipy"}},
	"ADCS_ESC3":                {5, 0.7, 0.5, []string{"certipy"}},
	"ADCS_ESC4":                {6, 0.6, 0.6, []string{"certipy"}},
	"ADCS_ESC7":                {4, 0.7, 0.7, []string{"certipy"}},
	"ADCS_ESC8":                {3, 0.8, 0.5, []string{"ntlmrelayx", "certipy"}},
	"ADCS_ESC9":                {3, 0.85, 0.35, []string{"certipy"}},
	"ADCS_ESC10":               {4, 0.75, 0.4, []string{"certipy"}},
	"ADCS_ESC13":               {4, 0.85, 0.3, []string{"certipy"}},
	"ADCS_ESC15":               {4, 0.7, 0.5, []string{"certipy"}},
	"UNCONSTRAINED_DELEGATION": {5, 0.8, 0.7, []string{"impacket-secretsdump"}},
	"CONSTRAINED_DELEGATION":   {4, 0.75, 0.6, []string{"impacket-getST", "impacket-secretsdump"}},
	"RBCD":                     {3, 0.85, 0.5, []string{"impacket-getST", "ntlmrelayx"}},
	"GenericWrite":             {7, 0.8, 0.6, []string{"nxc"}},
}

func rightProfileFor(right string) rightProfile {
	if p, ok := edgeWeight[right]; ok {
		return p
	}
	return rightProfile{10, 0.5, 0.5, nil}
}

// aceToEdge converts a parsed ACE block into a PrivilegeEdge.
// Returns nil if the ACE is a default/system ACE or lacks a valid trustee.
func aceToEdge(ace struct {
	aceType    string
	accessMask string
	objectType string
	trustee    string
	inBlock    bool
}, domain, targetName string) *core.PrivilegeEdge {
	if ace.trustee == "" || ace.accessMask == "" {
		return nil
	}

	// Skip built-in/system trustees that are noise
	skipPrefixes := []string{"BUILTIN", "NT AUTHORITY", "Everyone", "S-1-"}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(ace.trustee, p) {
			return nil
		}
	}

	right := ace.accessMask
	mask := strings.ToLower(ace.accessMask)
	switch {
	case strings.Contains(mask, "fullcontrol") || ace.accessMask == "0xf01ff":
		right = "GenericAll"
	case strings.Contains(mask, "controlaccess"):
		if ace.objectType != "" {
			right = ace.objectType
		} else {
			right = "ControlAccess"
		}
	case strings.Contains(mask, "writedacl"):
		right = "WriteDacl"
	case strings.Contains(mask, "writeproperty"):
		right = "WriteProperty"
	case strings.Contains(mask, "writeowner"):
		right = "WriteOwner"
	case strings.Contains(mask, "readproperty"):
		return nil
	}

	sourcePrincipal := cleanPrincipal(ace.trustee)

	targetPrincipal := cleanPrincipal(targetName)

	prof := rightProfileFor(right)

	return &core.PrivilegeEdge{
		SourcePrincipal: sourcePrincipal,
		TargetPrincipal: targetPrincipal,
		AccessRight:     right,
		EdgeType:        "acl",
		Domain:          domain,
		Source:          "daclread",
		Confidence:      0.85,
		Weight:          prof.Weight,
		Exploitability:  prof.Exploitability,
		Noise:           prof.Noise,
		Requires:        prof.Requires,
	}
}

// impersonateUserRe matches "username can impersonate target" patterns.
var impersonateUserRe = regexp.MustCompile(`(?i)(\S+)\s+can\s+impersonate\s+(\S+)`)

// sysadminRe matches "[+] name: sysadmin" or "name is a sysadmin" patterns.
var sysadminRe = regexp.MustCompile(`(?i)(\S+)\s*:\s*sysadmin|(\S+)\s+is\s+(?:a\s+)?sysadmin`)

// parseMSSQLImpersonations parses nxc mssql -M mssql_priv output into
// privilege edges. Two edge types are produced:
//
//   - MSSQL_EXECUTE_AS_LOGIN: a login can impersonate another principal
//   - MSSQL_SYSADMIN: a login has sysadmin role (target = "sa" by convention)
func parseMSSQLImpersonations(output, domain, host string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for "can impersonate" pattern
		if m := impersonateUserRe.FindStringSubmatch(line); len(m) > 0 {
			src := m[1]
			tgt := m[2]
			if src == "" || tgt == "" {
				continue
			}
			sp := src
			if !strings.Contains(sp, "\\") && domain != "" {
				sp = domain + "\\" + sp
			}
			tp := tgt
			if !strings.Contains(tp, "\\") && domain != "" {
				tp = domain + "\\" + tp
			}
			key := sp + "|" + tp + "|MSSQL_EXECUTE_AS_LOGIN"
			if seen[key] {
				continue
			}
			seen[key] = true
			edges = append(edges, core.PrivilegeEdge{
				SourcePrincipal: sp,
				TargetPrincipal: tp,
				AccessRight:     "MSSQL_EXECUTE_AS_LOGIN",
				EdgeType:        "mssql_impersonation",
				Domain:          domain,
				Source:          "mssql_priv",
				Confidence:      0.9,
				Weight:          5,
				Exploitability:  0.9,
				Noise:           0.4,
				Requires:        []string{"nxc", "mssql"},
			})
			continue
		}

		// Check for sysadmin status
		if m := sysadminRe.FindStringSubmatch(line); len(m) > 0 {
			login := m[1]
			if login == "" {
				login = m[2]
			}
			if login == "" {
				continue
			}
			lp := login
			if !strings.Contains(lp, "\\") && domain != "" {
				lp = domain + "\\" + lp
			}
			key := lp + "|sa|MSSQL_SYSADMIN"
			if seen[key] {
				continue
			}
			seen[key] = true
			edges = append(edges, core.PrivilegeEdge{
				SourcePrincipal: lp,
				TargetPrincipal: domain + "\\sa",
				AccessRight:     "MSSQL_SYSADMIN",
				EdgeType:        "mssql_impersonation",
				Domain:          domain,
				Source:          "mssql_priv",
				Confidence:      0.95,
				Weight:          2,
				Exploitability:  1.0,
				Noise:           0.5,
				Requires:        []string{"nxc", "mssql"},
			})

			// From sysadmin, xp_cmdshell provides SYSTEM-level execution on the host.
			xpKey := lp + "|SYSTEM@" + host + "|MSSQL_XP_CMDSHELL"
			if !seen[xpKey] {
				seen[xpKey] = true
				edges = append(edges, core.PrivilegeEdge{
					SourcePrincipal: lp,
					TargetPrincipal: "SYSTEM@" + host,
					AccessRight:     "MSSQL_XP_CMDSHELL",
					EdgeType:        "mssql_impersonation",
					Domain:          domain,
					Source:          "mssql_priv",
					Confidence:      0.9,
					Weight:          2,
					Exploitability:  1.0,
					Noise:           0.6,
					Requires:        []string{"nxc", "mssql"},
					Preconditions: []core.ExecutionPrecondition{
						{Kind: core.PrecondPortOpen, Target: host, Port: 1433, Description: "MSSQL port reachable"},
					},
				})
			}
		}
	}

	return edges
}

func parseSMBSessions(host core.Host, output string) []core.Session {
	var sessions []core.Session
	seen := make(map[string]struct{})

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if IsNoiseLine(line) {
			continue
		}

		users := DomainUserRe.FindAllString(line, -1)
		if len(users) == 0 {
			continue
		}

		srcIP := ""
		if m := fromRe.FindStringSubmatch(line); len(m) > 1 {
			srcIP = strings.TrimSpace(m[1])
		}

		for _, u := range users {
			key := host.IP + "|" + u + "|" + srcIP
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			sessions = append(sessions, core.Session{
				Host:     host.IP,
				Username: u,
				SourceIP: srcIP,
			})
		}
	}

	return sessions
}

// ldapResultRe matches data result lines from nxc LDAP queries.
// Format: LDAP  IP  PORT  TARGET  RESULT
var ldapResultRe = regexp.MustCompile(`^LDAP\s+\S+\s+\d+\s+\S+\s+(.+)$`)

// cleanPrincipal strips nxc auth noise and any domain prefix from a
// principal name. The Edge.Domain field already carries the DNS domain, so
// SourcePrincipal must be just the account name (e.g. "Administrator", "KINGSLANDING$").
func cleanPrincipal(raw string) string {
	s := strings.TrimSpace(raw)
	// Strip auth markers: "[+]", "[-]", "[*]"
	if strings.HasPrefix(s, "[") && len(s) > 2 {
		if idx := strings.Index(s[2:], "]"); idx >= 0 {
			s = strings.TrimSpace(s[idx+3:])
		}
	}
	// Strip auth artifacts: ":password (Pwn3d!)" or ":hash... (..)"
	if idx := strings.Index(s, ":"); idx >= 0 {
		beforeColon := s[:idx]
		afterColon := s[idx+1:]
		if len(beforeColon) > 0 && strings.HasPrefix(afterColon, " ") {
			s = beforeColon
		} else if len(beforeColon) > 0 && strings.Contains(afterColon, "(") && strings.Contains(afterColon, ")") {
			s = beforeColon
		}
	}
	// Strip any domain prefix (NetBIOS or DNS) — keep only the account name.
	// The Domain field on the edge carries the DNS domain.
	if idx := strings.LastIndex(s, "\\"); idx >= 0 {
		s = s[idx+1:]
	}
	return strings.TrimSpace(s)
}

// parseTrustedForDelegation parses nxc ldap --trusted-for-delegation output.
// The output lists computer accounts with the TRUSTED_FOR_DELEGATION flag set.
// Each such host can be used to extract TGTs of any user that authenticates to it.
func parseTrustedForDelegation(output, domain string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)

	for _, line := range strings.Split(output, "\n") {
		m := ldapResultRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		principal := cleanPrincipal(m[1])
		if principal == "" {
			continue
		}

		// Only computer accounts should have unconstrained delegation
		if !strings.HasSuffix(principal, "$") {
			continue
		}

		key := principal + "|UNCONSTRAINED_DELEGATION"
		if seen[key] {
			continue
		}
		seen[key] = true

		tgt := domain + "\\Domain Admins"

		edges = append(edges, core.PrivilegeEdge{
			SourcePrincipal: principal,
			TargetPrincipal: tgt,
			AccessRight:     "UNCONSTRAINED_DELEGATION",
			EdgeType:        "delegation",
			Domain:          domain,
			Source:          "nxc",
			Confidence:      0.85,
			Weight:          5,
			Exploitability:  0.8,
			Noise:           0.7,
			Requires:        []string{"impacket-secretsdump"}, // for extracting TGTs
		})
	}
	return edges
}

// parseConstrainedDelegation parses nxc ldap --find-delegation output.
// Output format (when entries exist):
//
//	PRINCIPAL_NAME  AllowedToDelegateTo:
//	  service/host1.domain
//	  service/host2.domain
func parseConstrainedDelegation(output, domain string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)

	var currentPrincipal string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		m := ldapResultRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		content := cleanPrincipal(m[1])
		if content == "" {
			continue
		}

		// Check for "Principal  AllowedToDelegateTo:" pattern
		if idx := strings.Index(content, "AllowedToDelegateTo"); idx >= 0 {
			raw := strings.TrimSpace(content[:idx])
			currentPrincipal = cleanPrincipal(raw)
			continue
		}

		// Continuation line: service/host pair (belongs to currentPrincipal)
		if currentPrincipal != "" && strings.Contains(content, "/") {
			parts := strings.SplitN(content, "/", 2)
			if len(parts) == 2 {
				tgtHost := strings.TrimSpace(parts[1])
				if colonIdx := strings.LastIndex(tgtHost, ":"); colonIdx >= 0 {
					tgtHost = tgtHost[:colonIdx]
				}
				tgt := tgtHost + "$"
				if !strings.Contains(tgt, "\\") && domain != "" {
					tgt = domain + "\\" + tgt
				}

				key := currentPrincipal + "|CONSTRAINED_DELEGATION|" + tgt
				if seen[key] {
					continue
				}
				seen[key] = true

				edges = append(edges, core.PrivilegeEdge{
					SourcePrincipal: currentPrincipal,
					TargetPrincipal: tgt,
					AccessRight:     "CONSTRAINED_DELEGATION",
					EdgeType:        "delegation",
					Domain:          domain,
					Source:          "nxc",
					Confidence:      0.85,
					Weight:          4,
					Exploitability:  0.75,
					Noise:           0.6,
					Requires:        []string{"impacket-getST", "impacket-secretsdump"},
				})
			}
			continue
		}

		// Non-continuation line without AllowedToDelegateTo resets principal
		if !strings.HasPrefix(content, "[") {
			currentPrincipal = ""
		}
	}
	return edges
}

// parseRBCDelegation parses nxc ldap --query output for msDS-AllowedToActOnBehalfOfOtherIdentity.
// RBCD allows a principal to impersonate any user to the target computer.
func parseRBCDelegation(output, domain string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)

	var currentDN string
	for _, line := range strings.Split(output, "\n") {
		m := ldapResultRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		content := cleanPrincipal(m[1])
		if content == "" {
			continue
		}

		if strings.HasPrefix(content, "dn:") {
			currentDN = strings.TrimSpace(strings.TrimPrefix(content, "dn:"))
			continue
		}

		if strings.Contains(content, "msDS-AllowedToActOnBehalfOfOtherIdentity") {
			if currentDN == "" {
				continue
			}

			targetComputer := extractComputerFromDN(currentDN)
			if targetComputer == "" {
				continue
			}

			src := targetComputer + "$"
			tgt := domain + "\\Domain Admins"

			key := src + "|RBCD|" + tgt
			if seen[key] {
				continue
			}
			seen[key] = true

			edges = append(edges, core.PrivilegeEdge{
				SourcePrincipal: src,
				TargetPrincipal: tgt,
				AccessRight:     "RBCD",
				EdgeType:        "delegation",
				Domain:          domain,
				Source:          "nxc",
				Confidence:      0.8,
				Weight:          3,
				Exploitability:  0.85,
				Noise:           0.5,
				Requires:        []string{"impacket-getST", "ntlmrelayx"},
			})
		}
	}
	return edges
}

// extractComputerFromDN extracts the computer name from an LDAP DN.
// Input: "CN=DC01$,OU=Domain Controllers,DC=sevenkingdoms,DC=local"
// Output: "DC01"
func extractComputerFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			name := strings.TrimPrefix(part, "CN=")
			name = strings.TrimSuffix(name, "$")
			return name
		}
	}
	return ""
}
