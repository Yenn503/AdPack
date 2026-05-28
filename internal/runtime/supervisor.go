package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"adpack/core"
)

var (
	ErrServiceNotFound = errors.New("runtime: service not found")
	ErrServiceExists   = errors.New("runtime: service already registered")
)

// ServiceSupervisor manages the lifecycle of long-lived background services.
// It implements core.RuntimeProvider and provides start/stop/query/event access.
type ServiceSupervisor struct {
	mu       sync.Mutex
	services map[string]*core.ManagedService
	events   chan core.ServiceEvent
}

// NewSupervisor creates a ready-to-use supervisor with a buffered event bus (capacity 256).
func NewSupervisor() *ServiceSupervisor {
	return &ServiceSupervisor{
		services: make(map[string]*core.ManagedService),
		events:   make(chan core.ServiceEvent, 256),
	}
}

// StartService registers and transitions a service to Running. The service
// must have a unique ID and a valid StopFn. The supervisor emits a
// EvServiceStarted event on success.
func (s *ServiceSupervisor) StartService(svc core.ManagedService) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.services[svc.ID]; exists {
		return ErrServiceExists
	}

	svc.State = core.ServiceRunning
	svc.LastHeartbeat = time.Now()
	if svc.ValidUntil.IsZero() {
		svc.ValidUntil = time.Now().Add(1 * time.Hour)
	}
	if svc.Events == nil {
		svc.Events = make(chan core.ServiceEvent, 64)
	}

	s.services[svc.ID] = &svc

	s.emitLocked(core.ServiceEvent{
		Type:      core.EvServiceStarted,
		ServiceID: svc.ID,
		Service:   svc.Type,
		Timestamp: time.Now(),
		Data:      svc.Config,
	})

	return nil
}

// StopService transitions a service to Stopped and calls its StopFn.
func (s *ServiceSupervisor) StopService(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.services[id]
	if !ok {
		return ErrServiceNotFound
	}

	svc.State = core.ServiceStopping
	err := svc.Stop()
	svc.State = core.ServiceStopped

	s.emitLocked(core.ServiceEvent{
		Type:      core.EvServiceStopped,
		ServiceID: id,
		Service:   svc.Type,
		Timestamp: time.Now(),
		Data:      map[string]any{"error": err},
	})

	delete(s.services, id)
	return err
}

// StopAll stops every managed service.
func (s *ServiceSupervisor) StopAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var lastErr error
	for id := range s.services {
		svc := s.services[id]
		svc.State = core.ServiceStopping
		if err := svc.Stop(); err != nil {
			lastErr = err
		}
		svc.State = core.ServiceStopped
		delete(s.services, id)
	}
	return lastErr
}

// Service returns a copy of the registered service by ID, or nil.
func (s *ServiceSupervisor) Service(id string) *core.ManagedService {
	s.mu.Lock()
	defer s.mu.Unlock()
	svc, ok := s.services[id]
	if !ok {
		return nil
	}
	copy := *svc
	return &copy
}

// Services returns a snapshot of all registered services.
func (s *ServiceSupervisor) Services() []*core.ManagedService {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*core.ManagedService, 0, len(s.services))
	for _, svc := range s.services {
		out = append(out, svc)
	}
	return out
}

// Events returns the supervisor-global event channel.
func (s *ServiceSupervisor) Events() <-chan core.ServiceEvent {
	return s.events
}

// Emit publishes a service event to all subscribers via the global channel.
func (s *ServiceSupervisor) Emit(evt core.ServiceEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emitLocked(evt)
}

func (s *ServiceSupervisor) emitLocked(evt core.ServiceEvent) {
	select {
	case s.events <- evt:
	default:
		// Drop event if channel is full — supervisor never blocks on emit.
	}
}

// Close shuts down the supervisor, stopping all services.
func (s *ServiceSupervisor) Close() error {
	return s.StopAll()
}

// StartRelay starts an ntlmrelayx listener as a managed service.
// Implements core.RuntimeProvider.
func (s *ServiceSupervisor) StartRelay(ctx context.Context, cfg core.RelayConfig) error {
	ntlmCfg := NTLMRelayConfig{
		Target:       cfg.Target,
		InterfaceIP:  cfg.InterfaceIP,
		SMBServer:    cfg.SMBServer,
		HTTPServer:   cfg.HTTPServer,
		SOCKSSupport: cfg.SOCKSSupport,
		ADCSMode:     cfg.ADCSMode,
		Template:     cfg.Template,
		Ports:        cfg.Ports,
		LootDir:      cfg.LootDir,
	}

	id := cfg.ID
	if id == "" {
		id = "ntlmrelayx-main"
	}
	label := cfg.Label
	if label == "" {
		label = "NTLM Relay Listener"
	}

	svc := NewNTLMRelayService(id, label, ntlmCfg)
	if err := s.StartService(*svc); err != nil {
		return err
	}

	svc = s.Service(id)
	return StartNTLMRelayService(svc, ntlmCfg, ctx)
}

// StartResponder starts a Responder.py poisoning listener as a managed service.
// Implements core.RuntimeProvider.
func (s *ServiceSupervisor) StartResponder(ctx context.Context, cfg core.ResponderConfig) error {
	respCfg := ResponderConfig{
		Interface:     cfg.Interface,
		Analyze:       cfg.Analyze,
		WPAD:          cfg.WPAD,
		ProxyAuth:     cfg.ProxyAuth,
		Basic:         cfg.Basic,
		LM:            cfg.LM,
		DisableESS:    cfg.DisableESS,
		DHCP:          cfg.DHCP,
		ForceWpadAuth: cfg.ForceWpadAuth,
		ExternalIP:    cfg.ExternalIP,
		Verbose:       cfg.Verbose,
	}

	id := cfg.ID
	if id == "" {
		id = "responder-main"
	}
	label := cfg.Label
	if label == "" {
		label = "Responder Poisoner"
	}

	svc := NewResponderService(id, label, respCfg)
	if err := s.StartService(*svc); err != nil {
		return err
	}

	svc = s.Service(id)
	return StartResponderService(svc, respCfg, ctx)
}

// StartCoercer starts an impacket-coercer loop as a managed service.
// Implements core.RuntimeProvider.
func (s *ServiceSupervisor) StartCoercer(ctx context.Context, cfg core.CoercerConfig) error {
	coercerCfg := CoercerConfig{
		SourceLabel: cfg.SourceLabel,
		InterfaceIP: cfg.InterfaceIP,
		Targets:     cfg.Targets,
		Methods:     cfg.Methods,
		Delay:       cfg.Delay,
	}

	id := cfg.ID
	if id == "" {
		id = "coercer-main"
	}
	label := cfg.Label
	if label == "" {
		label = "Coercer Trigger"
	}

	svc := NewCoercerService(id, label, coercerCfg)
	if err := s.StartService(*svc); err != nil {
		return err
	}

	svc = s.Service(id)
	return StartCoercerService(svc, coercerCfg, ctx)
}

// StartMitm6 starts a mitm6 IPv6 poisoner as a managed service.
// Implements core.RuntimeProvider.
func (s *ServiceSupervisor) StartMitm6(ctx context.Context, cfg core.Mitm6Config) error {
	mCfg := Mitm6Config{
		Interface:     cfg.Interface,
		Domain:        cfg.Domain,
		HostAllowList: cfg.HostAllowList,
		HostDenyList:  cfg.HostDenyList,
		IgnoreNoFQDN:  cfg.IgnoreNoFQDN,
		NoRA:          cfg.NoRA,
		RelayTarget:   cfg.RelayTarget,
		Verbose:       cfg.Verbose,
	}

	id := cfg.ID
	if id == "" {
		id = "mitm6-main"
	}
	label := cfg.Label
	if label == "" {
		label = "mitm6 IPv6 Poisoner"
	}

	svc := NewMitm6Service(id, label, mCfg)
	if err := s.StartService(*svc); err != nil {
		return err
	}

	svc = s.Service(id)
	return StartMitm6Service(svc, mCfg, ctx)
}

// ApplyToState synchronises the supervisor's runtime state into the given
// ADState. Ephemeral edges are appended to state.Edges, and active services
// are written into state.Runtime.
func (s *ServiceSupervisor) ApplyToState(state *core.ADState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svcMap := make(map[string]*core.ManagedService, len(s.services))
	for id, svc := range s.services {
		svcMap[id] = &core.ManagedService{
			ID:            svc.ID,
			Type:          svc.Type,
			Label:         svc.Label,
			State:         svc.State,
			Config:        svc.Config,
			ValidUntil:    svc.ValidUntil,
			LastHeartbeat: svc.LastHeartbeat,
		}
	}
	state.Runtime.ActiveServices = svcMap
}
