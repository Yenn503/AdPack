package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"adpack/core"
	"adpack/internal/runtime"
)

type mockResolver struct {
	name      string
	canHandle bool
	resolve   func(ctx context.Context, artifact ArtifactEvent) (*ResolvedArtifact, error)
}

func (m *mockResolver) Name() string            { return m.name }
func (m *mockResolver) CanHandle(t string) bool { return m.canHandle }
func (m *mockResolver) Resolve(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
	return m.resolve(ctx, a)
}

func TestExtractPFXPath_Normal(t *testing.T) {
	raw := "[*] Certificate written to /tmp/cert.pfx"
	got := extractPFXPath(raw)
	want := "/tmp/cert.pfx"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExtractPFXPath_NoMatch(t *testing.T) {
	raw := "relayed session from USER"
	got := extractPFXPath(raw)
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestExtractPFXPath_Empty(t *testing.T) {
	got := extractPFXPath("")
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestArtifactFromEvent_Valid(t *testing.T) {
	evt := core.ServiceEvent{
		ServiceID: "ntlmrelayx-main",
		Timestamp: time.Now(),
		Data: map[string]any{
			"artifact_type": "adcs.cert",
			"raw":           "[*] Certificate written to /tmp/cert.pfx",
		},
	}
	art := artifactFromEvent(evt)
	if art == nil {
		t.Fatal("expected non-nil artifact")
	}
	if art.Type != "adcs.cert" {
		t.Fatalf("expected type adcs.cert, got %q", art.Type)
	}
	if art.Path != "/tmp/cert.pfx" {
		t.Fatalf("expected path /tmp/cert.pfx, got %q", art.Path)
	}
	if art.Stage != "discovered" {
		t.Fatalf("expected stage discovered, got %q", art.Stage)
	}
}

func TestArtifactFromEvent_MissingType(t *testing.T) {
	evt := core.ServiceEvent{
		ServiceID: "ntlmrelayx-main",
		Data:      map[string]any{"raw": "some line"},
	}
	art := artifactFromEvent(evt)
	if art != nil {
		t.Fatal("expected nil for missing artifact_type")
	}
}

func TestAttachResolverPipeline_Dispatch(t *testing.T) {
	sup := runtime.NewSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handled := make(chan bool, 1)
	resolvers := []ArtifactResolver{&mockResolver{
		name:      "mock",
		canHandle: true,
		resolve: func(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
			handled <- true
			return &ResolvedArtifact{
				Type:       a.Type,
				Identity:   Identity{Name: "KINGSLANDING$", Domain: "sevenkingdoms.local"},
				Capability: "CERT_AUTH",
				Source:     "ESC8",
				Confidence: 0.85,
			}, nil
		},
	}}

	AttachResolverPipeline(ctx, sup, nil, resolvers...)
	sup.Emit(core.ServiceEvent{
		Type:      core.EvArtifactDiscovered,
		ServiceID: "ntlmrelayx-main",
		Service:   core.ServiceNTLMRelay,
		Timestamp: time.Now(),
		Data:      map[string]any{"artifact_type": "adcs.cert", "raw": "certificate written to /tmp/cert.pfx"},
	})

	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("resolver was not called")
	}
}

type mockRuntime struct {
	input  chan core.ServiceEvent // pipeline reads events from here
	output chan core.ServiceEvent // pipeline writes result events here
}

func newMockRuntime() *mockRuntime {
	return &mockRuntime{
		input:  make(chan core.ServiceEvent, 256),
		output: make(chan core.ServiceEvent, 256),
	}
}

func (m *mockRuntime) Events() <-chan core.ServiceEvent                                   { return m.input }
func (m *mockRuntime) Emit(evt core.ServiceEvent)                                         { m.output <- evt }
func (m *mockRuntime) StartService(svc core.ManagedService) error                         { return nil }
func (m *mockRuntime) StopService(id string) error                                        { return nil }
func (m *mockRuntime) StopAll() error                                                     { return nil }
func (m *mockRuntime) Service(id string) *core.ManagedService                             { return nil }
func (m *mockRuntime) Services() []*core.ManagedService                                   { return nil }
func (m *mockRuntime) StartRelay(ctx context.Context, cfg core.RelayConfig) error         { return nil }
func (m *mockRuntime) StartResponder(ctx context.Context, cfg core.ResponderConfig) error { return nil }
func (m *mockRuntime) StartCoercer(ctx context.Context, cfg core.CoercerConfig) error     { return nil }
func (m *mockRuntime) ApplyToState(state *core.ADState)                                   {}

func TestAttachResolverPipeline_Error(t *testing.T) {
	mrt := newMockRuntime()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolvers := []ArtifactResolver{&mockResolver{
		name:      "mock",
		canHandle: true,
		resolve: func(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
			return nil, errors.New("parse failed")
		},
	}}

	AttachResolverPipeline(ctx, mrt, nil, resolvers...)
	mrt.input <- core.ServiceEvent{
		Type:      core.EvArtifactDiscovered,
		ServiceID: "ntlmrelayx-main",
		Service:   core.ServiceNTLMRelay,
		Timestamp: time.Now(),
		Data:      map[string]any{"artifact_type": "adcs.cert", "raw": "certificate written to /tmp/cert.pfx"},
	}

	select {
	case evt := <-mrt.output:
		if evt.Type != core.EvArtifactResolveFail {
			t.Fatalf("expected EvArtifactResolveFail, got %v", evt.Type)
		}
		if evt.Data["resolver_name"] != "mock" {
			t.Fatalf("expected resolver_name mock, got %v", evt.Data["resolver_name"])
		}
	case <-time.After(time.Second):
		t.Fatal("expected failure event, got nothing")
	}
}

func TestAttachResolverPipeline_WrongEventType(t *testing.T) {
	sup := runtime.NewSupervisor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	called := false
	resolvers := []ArtifactResolver{&mockResolver{
		name:      "mock",
		canHandle: true,
		resolve: func(ctx context.Context, a ArtifactEvent) (*ResolvedArtifact, error) {
			called = true
			return nil, nil
		},
	}}

	AttachResolverPipeline(ctx, sup, nil, resolvers...)
	sup.Emit(core.ServiceEvent{
		Type:      core.EvHashCaptured,
		ServiceID: "responder-main",
		Service:   core.ServiceResponder,
		Timestamp: time.Now(),
		Data:      map[string]any{"artifact_type": "adcs.cert", "raw": "some line"},
	})

	time.Sleep(200 * time.Millisecond)
	if called {
		t.Fatal("resolver should not be called for non-artifact events")
	}
}
