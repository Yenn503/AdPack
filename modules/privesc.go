package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
	"adpack/tools"
)

func RunPrivesc(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for privilege escalation checks")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for privesc")
		result.Success = false
		return result
	}

	ctx := context.Background()
	target := tools.NetExecTarget{
		Protocol: "ldap", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	fmt.Println("[*] Checking GPP passwords in SYSVOL...")
	r, err := tools.NetExec.Run(ctx, target, "-M", []string{"gpp_password"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: "gpp", Key: "status", Value: "GPP check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
		fmt.Printf("[+] GPP check: %s\n", r.Stdout)
	}

	fmt.Println("[*] Checking ACL abuse paths...")
	r, err = tools.NetExec.Run(ctx, target, "-M", []string{"acl"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvUserEnumerated, Phase: core.PhasePrivEsc,
			Source: "acl", Key: "status", Value: "ACL check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
	}

	fmt.Println("[*] Checking ADCS vulnerable templates...")
	r, err = tools.NetExec.Run(ctx, target, "-M", []string{"adcs"})
	if err == nil && r.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: "adcs", Key: "status", Value: "ADCS check complete",
			RawOutput: r.Stdout, Timestamp: time.Now(),
		})
		fmt.Printf("[+] ADCS output: %s\n", r.Stdout)
	}

	fmt.Println("[*] Checking RBCD...")
	r, err = tools.NetExec.Run(ctx, target, "-M", []string{"rbcd"})
	if err == nil && r.Success {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "rbcd", Key: "status", Value: "RBCD check complete",
				RawOutput: r.Stdout, Timestamp: time.Now(),
			})
	}

	return result
}
