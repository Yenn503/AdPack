package core

import (
	"context"
	"time"
)

// ProviderConfig carries connection parameters used by all DirectoryProvider
// implementations. Configured once per phase invocation.
type ProviderConfig struct {
	Host      string
	Domain    string
	Username  string
	Password  string
	Hash      string
	EventSink ProviderEventSink
}

// DirectoryProvider abstracts the data source for graph analysis. Each method
// returns canonical entities without evidence — the caller decides how to
// project results into the evidence pipeline.
//
// This interface exists so that NetExec-based ingestion can be replaced with
// direct LDAP queries (or other backends) without rewriting the orchestration
// layer.
type DirectoryProvider interface {
	EnumerateComputers(ctx context.Context) ([]Computer, error)
	EnumerateGPOs(ctx context.Context) ([]GPO, error)
	EnumerateADCSTemplates(ctx context.Context) ([]ADCSTemplate, error)
	EnumerateSessions(ctx context.Context) ([]Session, error)
}

// ProviderEvent records the outcome of a single provider acquisition call.
// It is an acquisition-boundary event envelope, not a general-purpose log line.
//
// Stdout and Stderr carry the full raw output from the transport call. They
// are embedded inline so that replay and fuzz consumers have deterministic
// access to the input without external file references. Implementations that
// need to control log size should handle truncation or externalisation in
// the sink.
type ProviderEvent struct {
	Method      string
	Transport   string
	Target      string
	Fallback    bool
	DurationMS  int64
	StdoutBytes int
	StderrBytes int
	EntityCount int
	Error       string
	Timestamp   time.Time
	Stdout      string
	Stderr      string
}

// ProviderEventSink is the emission seam for acquisition events. The provider
// emits; the consumer decides persistence. Implementations must be safe for
// concurrent use.
type ProviderEventSink interface {
	Emit(ProviderEvent)
}

// NoopSink discards every event. This is the default sink used when no
// consumer is configured, keeping the hot path zero-cost.
type NoopSink struct{}

func (NoopSink) Emit(ProviderEvent) {}
