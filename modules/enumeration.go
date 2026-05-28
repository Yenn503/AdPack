package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

func RunEnumeration(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println(utils.ErrorStyle.Render("[!] No target available for enumeration. Run discovery first."))
		result.Success = false
		return result
	}

	// Use state creds if available
	dbDomain, dbUser, dbPass, _ := getCredential(state)
	if dbUser == "" || dbPass == "" {
		fmt.Println(utils.ErrorStyle.Render("[!] No credentials available for enumeration."))
		fmt.Println(utils.InfoStyle.Render("    Seed credentials with: adpack run discovery --domain <domain> --user <user> --password <pass>"))
		result.Success = false
		return result
	}

	// Prefer a DC matching our domain for LDAP enumeration
	if dc := findDC(state, dbDomain); dc.IP != "" {
		host = dc
	}

	user := dbUser
	pass := dbPass
	domain := dbDomain

	target := tools.NetExecTarget{
		Protocol: "ldap",
		Host:     host.IP,
		Port:     389,
		Domain:   domain,
		Username: user,
		Password: pass,
	}

	fmt.Println(utils.InfoStyle.Render(fmt.Sprintf("[*] Enumerating users on %s (%s)...", host.IP, domain)))

	ctx := context.Background()
	r, err := tools.NetExec.Run(ctx, target, "--users", nil)
	if err == nil && r.Success {
		users, descCreds := parseNetExecUsers(r.Stdout, domain)
		result.Users = append(result.Users, users...)
		result.Creds = append(result.Creds, descCreds...)

		for _, u := range users {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvUserEnumerated,
				Phase:      core.PhaseEnumeration,
				Source:     "netexec_ldap",
				Key:        u.Username,
				Value:      u.Description,
				Confidence: 1.0,
				Timestamp:  time.Now(),
			})
		}

		// Log description-based creds found
		for _, c := range descCreds {
			fmt.Println(utils.WarningStyle.Render(fmt.Sprintf(
				"  [!] Credential in description: %s\\%s : %s", c.Domain, c.Username, c.Secret)))
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type:       core.EvCredAcquired,
				Phase:      core.PhaseEnumeration,
				Source:     "ldap_description",
				Key:        fmt.Sprintf("%s\\%s", c.Domain, c.Username),
				Value:      c.Secret,
				Confidence: 0.9,
				Timestamp:  time.Now(),
			})
		}

		fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("[+] Enumerated %d users", len(users))))
		if len(descCreds) > 0 {
			fmt.Println(utils.SuccessStyle.Render(fmt.Sprintf("[+] Found %d credential(s) in user descriptions", len(descCreds))))
		}
	} else {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else {
			errMsg = r.Stderr
		}
		fmt.Println(utils.ErrorStyle.Render(fmt.Sprintf("[!] Enumeration failed: %s", errMsg)))
		result.Success = false
	}

	return result
}

// parseNetExecUsers parses the --users output from NetExec LDAP
// Format: LDAP  IP  PORT  DC1  username  <date>  badpw  description
func parseNetExecUsers(output, domain string) ([]core.User, []core.Credential) {
	var users []core.User
	var creds []core.Credential

	// Passwords commonly left in descriptions
	descPassPhrases := []string{
		"password", "passwd", "pass:", "pwd:", "cred:", "credentials:",
		"user password", "default password", "temp password",
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Strip the nxc prefix: LDAP  IP  PORT  HOSTNAME  ...
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		if parts[0] != "LDAP" {
			continue
		}
		// parts[0]=LDAP, parts[1]=IP, parts[2]=PORT, parts[3]=HOSTNAME
		userFields := parts[4:]
		if len(userFields) < 3 {
			continue
		}
		// Skip header/status lines
		first := userFields[0]
		if first == "-Username-" || first == "[*]" || first == "[+]" || first == "[-]" || first == "Enumerated" {
			continue
		}

		username := first
		description := ""
		if len(userFields) > 3 {
			description = strings.Join(userFields[3:], " ")
		}

		u := core.User{
			Username:       username,
			Domain:         domain,
			SAMAccountName: username,
			Enabled:        true,
			Description:    description,
			Source:         "netexec_ldap",
		}
		users = append(users, u)

		// Check if description contains a credential
		if description != "" {
			descLower := strings.ToLower(description)
			for _, phrase := range descPassPhrases {
				if strings.Contains(descLower, phrase) {
					// Extract the password value — take the last word or everything after the phrase
					secret := extractSecretFromDesc(description, phrase)
					if secret != "" {
						creds = append(creds, core.Credential{
							Type:     core.CredPlaintext,
							Username: username,
							Domain:   domain,
							Secret:   secret,
							Source:   "ldap_description",
						})
					}
					break
				}
			}
			// Also check for bare passwords in description (e.g. "czPm*R!@!$")
			// If description is short and looks like a password (no spaces, special chars)
			if !strings.Contains(description, " ") && len(description) >= 6 && looksLikePassword(description) {
				creds = append(creds, core.Credential{
					Type:     core.CredPlaintext,
					Username: username,
					Domain:   domain,
					Secret:   description,
					Source:   "ldap_description",
				})
			}
		}
	}

	return users, creds
}

// extractSecretFromDesc pulls the password value from a description string.
//
// Real-world AD descriptions often wrap or trail the password with punctuation:
//   - "Samwell Tarly (Password : Heartsbane)"          -> Heartsbane
//   - "John's password: 'P@ssw0rd!',"                   -> P@ssw0rd!
//   - 'service account [pwd: "ServicePass1!"]'          -> ServicePass1!
//
// We strip leading separators after the phrase, take the first whitespace
// delimited token, and then strip trailing/leading wrapping punctuation
// while preserving password-internal punctuation like '!', '@', '#'.
func extractSecretFromDesc(desc, phrase string) string {
	lower := strings.ToLower(desc)
	idx := strings.Index(lower, phrase)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimSpace(desc[idx+len(phrase):])
	// Strip leading separators that join the phrase to its value.
	rest = strings.TrimLeft(rest, ":= \t\"'`")
	// First whitespace-delimited token.
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return ""
	}
	tok := parts[0]
	// Strip wrapping punctuation that commonly bookends the value but is
	// never a legitimate password character at the boundary. Anything
	// inside the token (e.g. P@ss!w0rd) is preserved.
	const trailingJunk = `)]}>"',;.`
	const leadingJunk = `([{<"'`
	tok = strings.TrimRight(tok, trailingJunk)
	tok = strings.TrimLeft(tok, leadingJunk)
	return tok
}

// looksLikePassword returns true if the string looks like a password
func looksLikePassword(s string) bool {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	// Needs at least 3 of 4 character classes to look like a password
	count := 0
	for _, b := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if b {
			count++
		}
	}
	return count >= 3
}
