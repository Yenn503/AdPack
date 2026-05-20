package modules

import (
	"regexp"
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
	adcsVulnRe = regexp.MustCompile(`(?i)(ESC\d+|vulnerable|enabled)`)
	fromRe     = regexp.MustCompile(`(?i)\(from ([^)]+)\)`)
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

func parseADCSTemplates(output, domain string) []core.ADCSTemplate {
	var templates []core.ADCSTemplate
	seen := make(map[string]struct{})
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		if IsNoiseLine(line) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		vuln := fields[1]

		if !adcsVulnRe.MatchString(vuln) {
			vuln = ""
		}

		key := name + "@" + domain
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		templates = append(templates, core.ADCSTemplate{
			Name: name, Domain: domain, Vuln: vuln,
		})
	}
	return templates
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
