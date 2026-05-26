package cracker

import (
	"fmt"
	"sync"
	"time"
)

const (
	MaxQueueDepth    = 10000
	DedupTTL         = 30 * time.Minute
	RateLimitPerType = 10
)

type HashQueue struct {
	mu      sync.Mutex
	items   []*CrackJob
	seen    map[string]time.Time
	rateLim map[HashType]int
	events  chan CrackEvent
}

func NewHashQueue() *HashQueue {
	return &HashQueue{
		seen:    make(map[string]time.Time),
		rateLim: make(map[HashType]int),
		events:  make(chan CrackEvent, 1000),
	}
}

func (q *HashQueue) Enqueue(job *CrackJob) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= MaxQueueDepth {
		return fmt.Errorf("queue full (%d items)", MaxQueueDepth)
	}
	if exp, ok := q.seen[job.Hash]; ok && time.Since(exp) < DedupTTL {
		return nil
	}
	q.items = append(q.items, job)
	q.seen[job.Hash] = time.Now()
	q.events <- CrackEvent{Type: "hash_enqueued", Job: job}
	return nil
}

func (q *HashQueue) Dequeue() *CrackJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	bestIdx := 0
	for i := 1; i < len(q.items); i++ {
		if q.items[i].Priority < q.items[bestIdx].Priority {
			bestIdx = i
		}
	}
	job := q.items[bestIdx]
	q.items = append(q.items[:bestIdx], q.items[bestIdx+1:]...)
	return job
}

func (q *HashQueue) Events() chan CrackEvent {
	return q.events
}

func (q *HashQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
