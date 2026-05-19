package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"adpack/core"
	"adpack/tools"
)

type Runtime struct {
	Registry   *tools.Registry
	EventBus   *core.EventBus
	EventStore core.EventStore
	DAGStore   core.DAGStore
	Executors  *tools.ExecutorFactory
	Logger     *slog.Logger
	CampaignID string
}

func NewRuntime(store core.EventStore, dagStore core.DAGStore) *Runtime {
	reg := tools.NewRegistry()
	bus := core.NewEventBus(context.Background(), 4, 1024)
	ef := tools.NewExecutorFactory(reg)

	bus.SetStore(store)

	r := &Runtime{
		Registry:   reg,
		EventBus:   bus,
		EventStore: store,
		DAGStore:   dagStore,
		Executors:  ef,
		Logger:     slog.Default(),
		CampaignID: generateID(),
	}

	tools.RegisterBuiltinTools(reg)
	tools.RegisterBuiltinExecutors(reg)

	return r
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	return r.EventBus.Shutdown(ctx)
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}
