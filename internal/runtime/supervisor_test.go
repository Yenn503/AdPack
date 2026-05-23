package runtime

import (
	"errors"
	"testing"
	"time"

	"adpack/core"
)

func TestSupervisorStartStop(t *testing.T) {
	sup := NewSupervisor()

	svc := core.ManagedService{
		ID:     "test-relay-1",
		Type:   core.ServiceNTLMRelay,
		Label:  "test relay",
		StopFn: func() error { return nil },
	}

	if err := sup.StartService(svc); err != nil {
		t.Fatalf("StartService: %v", err)
	}

	got := sup.Service("test-relay-1")
	if got == nil {
		t.Fatal("service not found after start")
	}
	if got.State != core.ServiceRunning {
		t.Fatalf("expected Running, got %v", got.State)
	}

	if err := sup.StopService("test-relay-1"); err != nil {
		t.Fatalf("StopService: %v", err)
	}
	if sup.Service("test-relay-1") != nil {
		t.Fatal("service still registered after stop")
	}
}

func TestSupervisorStopAll(t *testing.T) {
	sup := NewSupervisor()

	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		sup.StartService(core.ManagedService{
			ID:     "svc-" + id,
			Type:   core.ServiceNTLMRelay,
			StopFn: func() error { return nil },
		})
	}

	if err := sup.StopAll(); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	if len(sup.Services()) != 0 {
		t.Fatal("services remain after StopAll")
	}
}

func TestSupervisorDuplicateID(t *testing.T) {
	sup := NewSupervisor()

	sup.StartService(core.ManagedService{
		ID:     "dup",
		Type:   core.ServiceNTLMRelay,
		StopFn: func() error { return nil },
	})

	err := sup.StartService(core.ManagedService{
		ID:     "dup",
		Type:   core.ServiceNTLMRelay,
		StopFn: func() error { return nil },
	})
	if !errors.Is(err, ErrServiceExists) {
		t.Fatalf("expected ErrServiceExists, got %v", err)
	}
}

func TestSupervisorStopNotFound(t *testing.T) {
	sup := NewSupervisor()
	err := sup.StopService("nonexistent")
	if !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound, got %v", err)
	}
}

func TestSupervisorEvents(t *testing.T) {
	sup := NewSupervisor()

	// Start a service and check the event channel
	svc := core.ManagedService{
		ID:     "event-test",
		Type:   core.ServiceNTLMRelay,
		Label:  "event test",
		StopFn: func() error { return nil },
	}

	sup.StartService(svc)

	select {
	case evt := <-sup.Events():
		if evt.Type != core.EvServiceStarted {
			t.Fatalf("expected EvServiceStarted, got %v", evt.Type)
		}
		if evt.ServiceID != "event-test" {
			t.Fatalf("expected service event-test, got %s", evt.ServiceID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for start event")
	}

	sup.StopService("event-test")
	select {
	case evt := <-sup.Events():
		if evt.Type != core.EvServiceStopped {
			t.Fatalf("expected EvServiceStopped, got %v", evt.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for stop event")
	}
}

func TestStartCoercer(t *testing.T) {
	sup := NewSupervisor()

	cfg := core.CoercerConfig{
		Delay: time.Second,
	}

	if err := sup.StartCoercer(t.Context(), cfg); err != nil {
		t.Fatalf("StartCoercer: %v", err)
	}

	svc := sup.Service("coercer-main")
	if svc == nil {
		t.Fatal("coercer service not found")
	}
	if svc.State != core.ServiceRunning {
		t.Fatalf("expected Running, got %v", svc.State)
	}
	if svc.Type != core.ServiceCoercion {
		t.Fatalf("expected ServiceCoercion, got %v", svc.Type)
	}

	if err := sup.StopService("coercer-main"); err != nil {
		t.Fatalf("StopService: %v", err)
	}

	if sup.Service("coercer-main") != nil {
		t.Fatal("service still registered after stop")
	}
}

func TestSupervisorApplyToState(t *testing.T) {
	sup := NewSupervisor()

	sup.StartService(core.ManagedService{
		ID:     "apply-test",
		Type:   core.ServiceNTLMRelay,
		StopFn: func() error { return nil },
	})

	state := &core.ADState{}
	sup.ApplyToState(state)

	if state.Runtime.ActiveServices == nil {
		t.Fatal("ActiveServices is nil after ApplyToState")
	}
	if _, ok := state.Runtime.ActiveServices["apply-test"]; !ok {
		t.Fatal("apply-test service not found in state.Runtime")
	}
}
