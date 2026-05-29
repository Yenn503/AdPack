package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// EncodePowerShell returns a base64-encoded PowerShell command string safe for
// use with powershell -EncodedCommand. This prevents injection through special
// characters in user-supplied values (GPO names, OUs, commands, etc.).
//
// The command is encoded as UTF-16LE (Unicode) as required by PowerShell's
// -EncodedCommand flag.
func EncodePowerShell(cmd string) string {
	utf16 := encodeUTF16LE(cmd)
	return base64.StdEncoding.EncodeToString(utf16)
}

// PowerShellCmd returns a complete powershell -EncodedCommand argument string
// ready for use with nxc -x or similar remote exec tools.
func PowerShellCmd(cmd string) string {
	return fmt.Sprintf("powershell -EncodedCommand %s", EncodePowerShell(cmd))
}

// PSModulePath returns the first existing module path from common locations.
func PSModulePath() string {
	for _, root := range []string{
		filepath.Join(os.Getenv("HOME"), ".local/share/powershell/Modules"),
		filepath.Join(os.Getenv("HOME"), ".powershell/modules"),
		"/usr/local/share/powershell/Modules",
		"/usr/share/powershell/Modules",
		"/opt/microsoft/powershell/Modules",
	} {
		if fi, err := os.Stat(root); err == nil && fi.IsDir() {
			return root
		}
	}
	return ""
}

// PSModuleInstalled checks whether a PowerShell module is installed.
func PSModuleInstalled(name string) bool {
	root := PSModulePath()
	if root == "" {
		return false
	}
	path := filepath.Join(root, name)
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// PSModuleExists checks if a PowerShell module is available by trying to
// import it. This is a more reliable check than PSModuleInstalled because
// modules may be in non-standard paths.
func PSModuleExists(name string) bool {
	out, _ := RunPSModule(context.Background(), name, "Get-Module", nil)
	return out.Success
}

// RunPSResult holds the output of a PowerShell module invocation.
type RunPSResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Success  bool
	Duration time.Duration
	JSON     any
}

// RunPSModule imports a PowerShell module and executes a command, returning
// both raw stdout and parsed JSON (when the command outputs ConvertTo-Json).
// The psCommand should include | ConvertTo-Json -Depth 10 if JSON output is wanted.
func RunPSModule(ctx context.Context, modulePath, psCommand string, args []string) (RunPSResult, error) {
	pwsh := findPowerShell()
	if pwsh == "" {
		return RunPSResult{}, fmt.Errorf("powershell not found")
	}

	importCmd := fmt.Sprintf(`Import-Module "%s" -Force; %s`, modulePath, psCommand)
	if len(args) > 0 {
		importCmd = fmt.Sprintf(`Import-Module "%s" -Force; %s`, modulePath,
			fmt.Sprintf(psCommand, args))
	}

	encoded := EncodePowerShell(importCmd)
	start := time.Now()
	cr := RunCommandCtx(ctx, pwsh, []string{"-NoP", "-NonI", "-EncodedCommand", encoded})
	r := RunPSResult{
		Stdout:   cr.Stdout,
		Stderr:   cr.Stderr,
		ExitCode: cr.ExitCode,
		Success:  cr.Success,
		Duration: time.Since(start),
	}

	if r.Success && r.Stdout != "" {
		var parsed any
		if err := json.Unmarshal([]byte(r.Stdout), &parsed); err == nil {
			r.JSON = parsed
		}
	}

	return r, nil
}

// findPowerShell returns the path to pwsh or powershell.
func findPowerShell() string {
	if p, err := exec.LookPath("pwsh"); err == nil {
		return p
	}
	if p, err := exec.LookPath("powershell"); err == nil {
		return p
	}
	return ""
}

// encodeUTF16LE converts a Go string (UTF-8) to UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	var b []byte
	for _, r := range s {
		if r <= 0xFFFF {
			b = append(b, byte(r), byte(r>>8))
		} else {
			// Surrogate pair for characters above BMP
			r -= 0x10000
			hi := 0xD800 + ((r >> 10) & 0x3FF)
			lo := 0xDC00 + (r & 0x3FF)
			b = append(b, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return b
}

// SanitizeFlag strips characters that could interfere with command-line
// argument parsing when a value is passed as a flag argument to nxc.
// This is a defense-in-depth measure for values that cannot use
// -EncodedCommand (e.g., simple single-command invocations).
func SanitizeFlag(s string) string {
	// Strip newlines, null bytes, and other control characters
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != ' ' {
			return -1
		}
		return r
	}, s)
	// Escape double quotes
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
