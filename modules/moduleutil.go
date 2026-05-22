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
