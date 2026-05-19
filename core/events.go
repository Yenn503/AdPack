package core

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type EventType string

const (
	EventCredentialValidated EventType = "credential.validated"
	EventAdminAccessConfirmed EventType = "credential.admin.confirmed"
	EventKerberoastableFound EventType = "kerberos.roastable.found"
	EventASREPRoastableFound EventType = "kerberos.asrep.found"
	EventDACompromise        EventType = "credential.da.compromise"
	EventEDRDetected         EventType = "evasion.edr.detected"
	EventADCSExploitable     EventType = "adcs.vulnerable"
	EventSessionFound        EventType = "session.found"
	EventHostDiscovered      EventType = "host.discovered"
	EventPhaseComplete       EventType = "phase.complete"
	EventPhaseFailed         EventType = "phase.failed"
	EventDCSyncPossible      EventType = "credential.dcsync.possible"
	EventRBCDExploitable     EventType = "ad.rbcd.exploitable"
	EventShadowCredAdded     EventType = "credential.shadow.added"
	EventExecutionStarted    EventType = "execution.started"
	EventExecutionFailed     EventType = "execution.failed"
	EventExecutionComplete   EventType = "execution.complete"
)

type EventClass int

const (
	EventClassCritical   EventClass = iota
	EventClassBestEffort
	EventClassTelemetry
	EventClassDebug
)

func (c EventClass) String() string {
	switch c {
	case EventClassCritical:
		return "critical"
	case EventClassBestEffort:
		return "besteffort"
	case EventClassTelemetry:
		return "telemetry"
	case EventClassDebug:
		return "debug"
	default:
		return "unknown"
	}
}

func eventClass(typ EventType) EventClass {
	switch typ {
	case EventDACompromise, EventPhaseComplete, EventPhaseFailed,
		EventExecutionStarted, EventExecutionComplete, EventExecutionFailed,
		EventDCSyncPossible, EventShadowCredAdded, EventRBCDExploitable:
		return EventClassCritical
	case EventCredentialValidated, EventAdminAccessConfirmed,
		EventKerberoastableFound, EventASREPRoastableFound,
		EventSessionFound, EventHostDiscovered, EventADCSExploitable:
		return EventClassBestEffort
	case EventEDRDetected:
		return EventClassDebug
	default:
		return EventClassBestEffort
	}
}

type Event struct {
	Class      EventClass
	Type       EventType
	Source     string
	Timestamp  time.Time
	Evidence   *EvidenceEntry
	Metadata   map[string]any
	TraceID    string
	CampaignID string
}

const (
	defaultQueueSize = 1024
	ringBufferSize   = 10000
	publishRetries   = 3
)

type EventBus struct {
	queue     chan Event
	queueSize int
	workers   int
	subs      map[EventType][]func(Event)
	mu        sync.RWMutex
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	ring      []Event
	ringPos   int
	ringCount int
	ringMu    sync.RWMutex
	closed    bool
	closeMu   sync.Mutex
	store     EventStore
}

func NewEventBus(parent context.Context, workers, queueSize int) *EventBus {
	ctx, cancel := context.WithCancel(parent)
	b := &EventBus{
		queue:     make(chan Event, queueSize),
		queueSize: queueSize,
		workers:   workers,
		subs:      make(map[EventType][]func(Event)),
		ctx:       ctx,
		cancel:    cancel,
		ring:      make([]Event, ringBufferSize),
	}
	for i := 0; i < workers; i++ {
		b.wg.Add(1)
		go b.worker()
	}
	return b
}

func (b *EventBus) worker() {
	defer b.wg.Done()
	for evt := range b.queue {
		b.appendHistory(evt)
		b.dispatch(evt)
		if b.store != nil {
			if err := b.store.AppendEvent(evt); err != nil {
				slog.Error("event persist failed",
					"type", evt.Type, "error", err)
			}
		}
	}
}

func (b *EventBus) dispatch(evt Event) {
	b.mu.RLock()
	handlers := b.subs[evt.Type]
	b.mu.RUnlock()

	for _, h := range handlers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("event handler panic",
						"event_type", evt.Type,
						"panic", r,
					)
				}
			}()
			h(evt)
		}()
	}
}

func (b *EventBus) Subscribe(eventType EventType, handler func(Event)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[eventType] = append(b.subs[eventType], handler)
}

func (b *EventBus) SetStore(s EventStore) {
	b.store = s
}

func (b *EventBus) Publish(evt Event) {
	evt.Class = eventClass(evt.Type)
	evt.Timestamp = time.Now()

	switch evt.Class {
	case EventClassCritical:
		b.publishCritical(evt)
	default:
		b.publishNonBlocking(evt)
	}
}

func (b *EventBus) publishCritical(evt Event) {
	if b.isClosed() {
		slog.Error("event bus closed, critical event dropped",
			"type", evt.Type, "trace_id", evt.TraceID)
		return
	}
	for attempt := 0; attempt < publishRetries; attempt++ {
		select {
		case b.queue <- evt:
			return
		case <-b.ctx.Done():
			slog.Error("event bus shutting down, critical event lost",
				"type", evt.Type, "trace_id", evt.TraceID)
			return
		default:
			if attempt < publishRetries-1 {
				select {
				case b.queue <- evt:
					return
				case <-time.After(50 * time.Millisecond):
					continue
				}
			}
		}
	}
	slog.Error("event bus queue full after retries, persisting critical event",
		"type", evt.Type, "trace_id", evt.TraceID)
	if err := b.persistEvent(evt); err != nil {
		slog.Error("failed to persist critical event",
			"type", evt.Type, "error", err)
	}
}

func (b *EventBus) publishNonBlocking(evt Event) {
	if b.isClosed() {
		return
	}
	select {
	case b.queue <- evt:
	case <-b.ctx.Done():
	default:
	}
}

func (b *EventBus) isClosed() bool {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()
	return b.closed
}

func (b *EventBus) appendHistory(evt Event) {
	b.ringMu.Lock()
	defer b.ringMu.Unlock()
	b.ring[b.ringPos] = evt
	b.ringPos = (b.ringPos + 1) % ringBufferSize
	if b.ringCount < ringBufferSize {
		b.ringCount++
	}
}

func (b *EventBus) History(eventType EventType) []Event {
	b.ringMu.RLock()
	defer b.ringMu.RUnlock()
	if b.ringCount == 0 {
		return nil
	}
	if eventType == "" {
		out := make([]Event, b.ringCount)
		if b.ringCount < ringBufferSize {
			copy(out, b.ring[:b.ringCount])
		} else {
			start := b.ringPos
			first := append(b.ring[start:], b.ring[:start]...)
			copy(out, first)
		}
		return out
	}
	var out []Event
	count := b.ringCount
	if count > ringBufferSize {
		count = ringBufferSize
	}
	start := 0
	wrap := false
	if b.ringCount >= ringBufferSize {
		start = b.ringPos
		wrap = true
	}
	for i := 0; i < count; i++ {
		idx := (start + i) % ringBufferSize
		if b.ring[idx].Type == eventType {
			out = append(out, b.ring[idx])
		}
		if wrap && idx == start-1 {
			break
		}
	}
	return out
}

func (b *EventBus) Shutdown(ctx context.Context) error {
	b.cancel()
	b.closeMu.Lock()
	b.closed = true
	b.closeMu.Unlock()
	close(b.queue)
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *EventBus) persistEvent(evt Event) error {
	if b.store != nil {
		return b.store.AppendEvent(evt)
	}
	return nil
}

func NewEvent(typ EventType, source string, evidence *EvidenceEntry, metadata map[string]any) Event {
	return Event{
		Type:      typ,
		Source:    source,
		Timestamp: time.Now(),
		Evidence:  evidence,
		Metadata:  metadata,
	}
}
