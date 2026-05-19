package core

import "time"

type EventStore interface {
	AppendEvent(evt Event) error
	Replay(from time.Time) ([]Event, error)
}
