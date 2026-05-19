package engine

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"adpack/core"
	"adpack/tools"
)

type WorkerPool struct {
	workers int
	queue   chan *core.DAGNode
	wg      sync.WaitGroup

	runtime *Runtime
}

func NewWorkerPool(n int, rt *Runtime) *WorkerPool {
	return &WorkerPool{
		workers: n,
		queue:   make(chan *core.DAGNode, 1024),
		runtime: rt,
	}
}

func (wp *WorkerPool) Start(ctx context.Context) {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx)
	}
}

func (wp *WorkerPool) Stop() {
	close(wp.queue)
	wp.wg.Wait()
}

func (wp *WorkerPool) Enqueue(n *core.DAGNode) {
	wp.queue <- n
}

func (wp *WorkerPool) worker(ctx context.Context) {
	defer wp.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case n, ok := <-wp.queue:
			if !ok {
				return
			}
			wp.execute(ctx, n)
		}
	}
}

func (wp *WorkerPool) execute(ctx context.Context, n *core.DAGNode) {
	log := wp.runtime.Logger.With("node", n.ID, "tool", n.Tool)
	log.Info("executing node")

	n.Status = core.NodeRunning
	n.StartedAt = time.Now()
	if err := wp.runtime.DAGStore.UpdateNodeStatus(n.ID, core.NodeRunning, json.RawMessage("{}"), ""); err != nil {
		log.Error("failed to mark node running", "error", err)
	}

	tool, ok := wp.runtime.Registry.FindTool(n.Tool)
	if !ok {
		n.Status = core.NodeFailed
		n.LastError = "tool not found: " + n.Tool
		wp.runtime.DAGStore.UpdateNodeStatus(n.ID, core.NodeFailed, n.Output, n.LastError)
		wp.runtime.EventBus.Publish(core.Event{
			Type:   core.EventExecutionFailed,
			Source: n.Tool,
			Metadata: map[string]any{
				"node_id": n.ID, "error": n.LastError,
			},
		})
		return
	}

	var req tools.ExecutionRequest
	if len(n.Input) > 0 && string(n.Input) != "{}" {
		if err := json.Unmarshal(n.Input, &req); err != nil {
			log.Error("failed to unmarshal input", "error", err)
		}
	}

	wp.runtime.EventBus.Publish(core.Event{
		Type:   core.EventExecutionStarted,
		Source: n.Tool,
		Metadata: map[string]any{
			"node_id": n.ID, "phase": string(n.Phase),
		},
	})

	result, err := tool.Run(ctx, req)
	output, _ := json.Marshal(result)
	n.Output = output

	if err != nil || !result.Success {
		n.Status = core.NodeFailed
		n.LastError = "execution failed"
		if err != nil {
			n.LastError = err.Error()
		}
		wp.runtime.DAGStore.UpdateNodeStatus(n.ID, core.NodeFailed, output, n.LastError)
		wp.runtime.EventBus.Publish(core.Event{
			Type:   core.EventExecutionFailed,
			Source: n.Tool,
			Metadata: map[string]any{
				"node_id": n.ID, "error": n.LastError,
			},
		})
		return
	}

	n.Status = core.NodeSuccess
	wp.runtime.DAGStore.UpdateNodeStatus(n.ID, core.NodeSuccess, output, "")
	wp.runtime.EventBus.Publish(core.Event{
		Type:   core.EventExecutionComplete,
		Source: n.Tool,
		Metadata: map[string]any{
			"node_id": n.ID,
		},
	})
	log.Info("node complete")
}
