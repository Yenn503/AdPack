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
