package modules

import (
	"fmt"
	"os"
	"strings"

	"adpack/utils"
)

// KerberosManager handles TGT acquisition, listing, destruction, and S4U.
type KerberosManager struct{}

// GetTGT obtains a TGT using impacket-getTGT and sets KRB5CCNAME.
func (k *KerberosManager) GetTGT(user, domain, password, hash, aesKey, dcIP string) error {
	ccacheFile := fmt.Sprintf("/tmp/krb5cc_%s_%s", domain, user)
	args := []string{"-dc-ip", dcIP, "-ccache", ccacheFile}
	if password != "" {
		args = append(args, fmt.Sprintf("%s/%s:%s", domain, user, password))
	} else if hash != "" {
		args = append(args, "-hashes", hash, fmt.Sprintf("%s/%s", domain, user))
	} else if aesKey != "" {
		args = append(args, "-aesKey", aesKey, fmt.Sprintf("%s/%s", domain, user))
	} else {
		return fmt.Errorf("no credential provided (password, hash, or AES key required)")
	}

	utils.Step(fmt.Sprintf("Requesting TGT for %s@%s...", user, domain))
	result := utils.RunCommand("impacket-getTGT", args...)
	if !result.Success {
		return fmt.Errorf("getTGT failed: %s", result.Stderr)
	}

	// impacket-getTGT outputs the ccache file path; set KRB5CCNAME
	os.Setenv("KRB5CCNAME", ccacheFile)
	utils.StepOk(fmt.Sprintf("TGT obtained: %s", ccacheFile))
	fmt.Printf("  export KRB5CCNAME=%s\n", ccacheFile)
	return nil
}

// ListTickets lists current Kerberos tickets via klist.
func (k *KerberosManager) ListTickets() error {
	ccache := os.Getenv("KRB5CCNAME")
	if ccache == "" {
		ccache = "/tmp/krb5cc_0" // default
	}
	result := utils.RunCommand("klist", "-c", ccache)
	if !result.Success {
		return fmt.Errorf("klist failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

// DestroyTickets destroys the current Kerberos ticket cache.
func (k *KerberosManager) DestroyTickets() error {
	ccache := os.Getenv("KRB5CCNAME")
	if ccache == "" {
		utils.StepInfo("No KRB5CCNAME set — nothing to destroy")
		return nil
	}
	if err := os.Remove(ccache); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove ccache: %w", err)
	}
	os.Unsetenv("KRB5CCNAME")
	utils.StepOk(fmt.Sprintf("Ticket cache destroyed: %s", ccache))
	return nil
}

// S4U performs S4U2self + S4U2proxy to impersonate a user to a service.
func (k *KerberosManager) S4U(user, domain, password, hash, impersonate, spn, dcIP string) error {
	if impersonate == "" || spn == "" {
		return fmt.Errorf("--impersonate and --spn are required for S4U")
	}

	// First get a TGT
	if err := k.GetTGT(user, domain, password, hash, "", dcIP); err != nil {
		return fmt.Errorf("get TGT for S4U: %w", err)
	}

	spnParts := strings.SplitN(spn, "/", 2)
	altservice := spn
	if len(spnParts) == 2 {
		altservice = spnParts[0] + "/" + spnParts[1] + "@" + strings.ToUpper(domain)
	}
	args := []string{
		"-k", "-no-pass",
		"-dc-ip", dcIP,
		"-spn", spn,
		"-impersonate", impersonate,
		"-altservice", altservice,
		fmt.Sprintf("%s/%s@%s", domain, user, strings.ToUpper(domain)),
	}

	utils.Step(fmt.Sprintf("S4U: %s impersonating %s → %s", user, impersonate, spn))
	result := utils.RunCommand("impacket-getST", args...)
	if !result.Success {
		return fmt.Errorf("getST failed: %s", result.Stderr)
	}

	// getST saves to impersonate.ccache
	s4uCC := fmt.Sprintf("%s.ccache", impersonate)
	if _, err := os.Stat(s4uCC); err == nil {
		os.Setenv("KRB5CCNAME", s4uCC)
		utils.StepOk(fmt.Sprintf("S4U ticket saved: %s", s4uCC))
		fmt.Printf("  export KRB5CCNAME=%s\n", s4uCC)
	}
	fmt.Println(result.Stdout)
	return nil
}

// GenerateKrb5Conf creates a krb5.conf for the given domain.
func (k *KerberosManager) GenerateKrb5Conf(domain, dcIP string) error {
	realm := strings.ToUpper(domain)
	conf := fmt.Sprintf(`[libdefaults]
	default_realm = %s
	dns_lookup_realm = false
	dns_lookup_kdc = true
	ticket_lifetime = 24h
	renew_lifetime = 7d
	forwardable = true

[realms]
	%s = {
		kdc = %s
		admin_server = %s
	}

[domain_realm]
	.%s = %s
	%s = %s
`, realm, realm, dcIP, dcIP, domain, realm, domain, realm)

	path := fmt.Sprintf("/tmp/krb5_%s.conf", domain)
	if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write krb5.conf: %w", err)
	}
	os.Setenv("KRB5_CONFIG", path)
	utils.StepOk(fmt.Sprintf("krb5.conf generated: %s", path))
	fmt.Printf("  export KRB5_CONFIG=%s\n", path)
	return nil
}
