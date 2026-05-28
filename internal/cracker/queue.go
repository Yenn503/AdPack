package cracker

import (
	"fmt"
	"sync"
	"time"
)

const (
	MaxQueueDepth = 10000
	DedupTTL      = 30 * time.Minute
)

type HashQueue struct {
	mu     sync.Mutex
	items  []*CrackJob
	seen   map[string]time.Time
	events chan CrackEvent
}

func NewHashQueue() *HashQueue {
	q := &HashQueue{
		seen:   make(map[string]time.Time),
		events: make(chan CrackEvent, 1000),
	}
	q.startCleanupLoop()
	return q
}

func (q *HashQueue) startCleanupLoop() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			q.mu.Lock()
			now := time.Now()
			for hash, enqueued := range q.seen {
				if now.Sub(enqueued) > DedupTTL {
					delete(q.seen, hash)
				}
			}
			q.mu.Unlock()
		}
	}()
}

func (q *HashQueue) Enqueue(job *CrackJob) error {
	q.mu.Lock()
	if len(q.items) >= MaxQueueDepth {
		q.mu.Unlock()
		return fmt.Errorf("queue full (%d items)", MaxQueueDepth)
	}
	if exp, ok := q.seen[job.Hash]; ok && time.Since(exp) < DedupTTL {
		q.mu.Unlock()
		return nil
	}
	q.items = append(q.items, job)
	q.seen[job.Hash] = time.Now()
	q.mu.Unlock()
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
