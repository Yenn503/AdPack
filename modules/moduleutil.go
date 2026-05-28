package modules

import (
	"context"

	"adpack/core"
)

var ExecutorFactory core.ExecutorFactory = func(_ core.HostRef, _, _, _, _ string) core.Executor {
	return core.ExecutorFunc(func(_ context.Context, _ core.Action) core.ActionResult {
		return core.ActionResult{Success: false, Error: "executor not configured"}
	})
}

// RuntimeFactory is injected by cmd/ to provide a RuntimeProvider for modules.
// If nil, runtime-dependent features are skipped (headless/offline mode).
var RuntimeFactory func() core.RuntimeProvider

// CapabilityRegistry is injected from cmd/. Default nil (noop).
var CapabilityRegistry *core.CapabilityRegistry

// EnqueueHash is injected from cmd/ to feed captured hashes into the cracker pipeline.
// Default noop so headless tests don't panic.
var EnqueueHash func(hashType, hash, username, domain string)

// findDC returns the first DC host from state matching the given domain.
// If domain is empty or no DC matches, returns any DC. Falls back to zero-value.
func findDC(state *core.ADState, domain string) core.Host {
	var fallback core.Host
	for _, h := range state.Hosts {
		if !h.IsDC {
			continue
		}
		if fallback.IP == "" {
			fallback = h
		}
		if domain != "" && h.Domain == domain {
			return h
		}
	}
	return fallback
}
