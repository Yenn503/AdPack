package core

import (
	"context"
	"time"
)

// ServiceType identifies the kind of long-lived background service.
type ServiceType string

const (
	ServiceNTLMRelay ServiceType = "ntlmrelayx"
	ServiceResponder ServiceType = "responder"
	ServiceCoercion  ServiceType = "coercer"
	ServiceWebDAV    ServiceType = "webdav"
	ServiceHTTPRelay ServiceType = "http_relay"
	ServiceResolver  ServiceType = "resolver"
)

// ServiceState tracks the lifecycle phase of a managed service.
type ServiceState int

const (
	ServiceStopped  ServiceState = 0
	ServiceStarting ServiceState = 1
	ServiceRunning  ServiceState = 2
	ServiceFailed   ServiceState = 3
	ServiceDegraded ServiceState = 4
	ServiceStopping ServiceState = 5
)

// ServiceEventType categorises events emitted by managed services.
type ServiceEventType string

const (
	EvServiceStarted      ServiceEventType = "service.started"
	EvServiceStopped      ServiceEventType = "service.stopped"
	EvServiceFailed       ServiceEventType = "service.failed"
	EvServiceHeartbeat    ServiceEventType = "service.heartbeat"
	EvSessionCaptured     ServiceEventType = "session.captured"
	EvHashCaptured        ServiceEventType = "hash.captured"
	EvEdgeMaterialized    ServiceEventType = "edge.materialized"
	EvEdgeInvalidated     ServiceEventType = "edge.invalidated"
	EvCredentialAcquired  ServiceEventType = "credential.acquired"
	EvCoerceAttempt       ServiceEventType = "coerce.attempt"
	EvCoerceSuccess       ServiceEventType = "coerce.success"
	EvArtifactDiscovered  ServiceEventType = "artifact.discovered"
	EvArtifactResolved    ServiceEventType = "artifact.resolved"
	EvArtifactResolveFail ServiceEventType = "artifact.resolve.failed"
)

// ServiceEvent is emitted by a ManagedService or the supervisor to signal
// state transitions, captured material, or graph-mutating observations.
type ServiceEvent struct {
	Type      ServiceEventType `json:"type"`
	ServiceID string           `json:"service_id"`
	Service   ServiceType      `json:"service_type"`
	Timestamp time.Time        `json:"timestamp"`
	Data      map[string]any   `json:"data,omitempty"`
}

// ManagedService represents a single long-lived background process managed
// by the ServiceSupervisor. Examples: ntlmrelayx listener, Responder, WebDAV.
type ManagedService struct {
	ID            string            `json:"id"`
	Type          ServiceType       `json:"type"`
	Label         string            `json:"label,omitempty"`
	State         ServiceState      `json:"state"`
	Config        map[string]any    `json:"config,omitempty"`
	ValidUntil    time.Time         `json:"valid_until,omitempty"`
	LastHeartbeat time.Time         `json:"last_heartbeat,omitempty"`
	StopFn        func() error      `json:"-"` // called by supervisor to stop
	Events        chan ServiceEvent `json:"-"`
}

// Stop calls the registered stop function if set.
func (s *ManagedService) Stop() error {
	if s.StopFn != nil {
		return s.StopFn()
	}
	return nil
}

// IsRunning returns true when the service is in a running or degraded state.
func (s *ManagedService) IsRunning() bool {
	return s.State == ServiceRunning || s.State == ServiceDegraded
}

// RuntimeProvider is the interface for starting, stopping, and querying
// long-lived background services. Implemented by internal/runtime/supervisor.
type RuntimeProvider interface {
	StartService(svc ManagedService) error
	StopService(id string) error
	StopAll() error
	Service(id string) *ManagedService
	Services() []*ManagedService
	Events() <-chan ServiceEvent
	// StartRelay starts an ntlmrelayx listener as a managed service.
	// Returns after the process is launched; captured material arrives via Events().
	StartRelay(ctx context.Context, cfg RelayConfig) error
	// StartResponder starts a Responder.py poisoning listener as a managed service.
	StartResponder(ctx context.Context, cfg ResponderConfig) error
	// StartCoercer starts an impacket-coercer instance as a managed service.
	StartCoercer(ctx context.Context, cfg CoercerConfig) error
	// Emit publishes a service event to the runtime event bus.
	Emit(evt ServiceEvent)
	// ApplyToState synchronises active services and ephemeral edges into ADState.
	ApplyToState(state *ADState)
}

// ResponderConfig carries parameters for starting a Responder poisoning listener.
// Defined in core so modules/ can configure responders without importing internal/.
type ResponderConfig struct {
	ID            string // service ID for the supervisor
	Label         string // human-readable label
	Interface     string // network interface (e.g. eth0)
	Analyze       bool   // passive/analyze mode (no poisoning)
	WPAD          bool   // start WPAD rogue proxy server
	ProxyAuth     bool   // force NTLM/Basic proxy auth
	Basic         bool   // downgrade to HTTP Basic auth
	LM            bool   // force LM hashing downgrade
	DisableESS    bool   // NTLMv1 downgrade
	DHCP          bool   // DHCPv4 poisoning
	ForceWpadAuth bool   // force auth on wpad.dat retrieval
	ExternalIP    string // spoofed IP for poisoned answers
	Verbose       bool   // increased output
}

// RuntimeState holds the dynamic runtime view of active services and
// time-bound edges. Lives on ADState and is mutated by the supervisor.
type RuntimeState struct {
	ActiveServices map[string]*ManagedService `json:"active_services"`
	EphemeralEdges []PrivilegeEdge            `json:"ephemeral_edges,omitempty"`
}

// RelayConfig carries parameters for starting an ntlmrelayx listener.
// Defined in core so modules/ can configure relays without importing internal/.
type RelayConfig struct {
	ID           string         // service ID for the supervisor
	Label        string         // human-readable label
	Target       string         // e.g. ldap://dc01.sevenkingdoms.local
	InterfaceIP  string         // listening interface IP
	SMBServer    bool           // enable SMB server
	HTTPServer   bool           // enable HTTP server
	SOCKSSupport bool           // enable SOCKS proxy mode
	ADCSMode     bool           // enable ADCS relay mode
	Template     string         // certificate template name (ADCS mode)
	Ports        map[string]int // per-protocol port overrides
	LootDir      string         // directory to store captured material
}

// CoercerConfig carries parameters for running impacket-coercer.
type CoercerConfig struct {
	ID          string        // service ID for the supervisor
	Label       string        // human-readable label
	SourceLabel string        // instance identifier for edge attribution
	InterfaceIP string        // listener IP coerced targets auth against
	Targets     []string      // IPs/hostnames to coerce
	Methods     []string      // smb, http, ldap (empty = all)
	Delay       time.Duration // sleep between rounds
}
