package cracker

import "testing"

func TestHashQueueDedup(t *testing.T) {
	q := NewHashQueue()
	job := &CrackJob{HashType: HashKRB5TGS, Hash: "same-hash", Priority: PriorityOther}
	if err := q.Enqueue(job); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := q.Enqueue(job); err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	if q.Len() != 1 {
		t.Errorf("expected 1 item after dedup, got %d", q.Len())
	}
}

func TestHashQueuePriority(t *testing.T) {
	q := NewHashQueue()
	q.Enqueue(&CrackJob{HashType: HashNTLM, Hash: "low", Priority: PriorityOther})
	q.Enqueue(&CrackJob{HashType: HashNTLM, Hash: "high", Priority: PriorityDA})
	job := q.Dequeue()
	if job.Hash != "high" {
		t.Errorf("expected high priority job, got %s (priority %d)", job.Hash, job.Priority)
	}
}

func TestHashQueueBackpressure(t *testing.T) {
	q := NewHashQueue()
	if err := q.Enqueue(&CrackJob{Hash: "t1", Priority: PriorityOther}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
}

func TestHashQueueEmptyDequeue(t *testing.T) {
	q := NewHashQueue()
	if job := q.Dequeue(); job != nil {
		t.Errorf("expected nil from empty queue, got %v", job)
	}
}

func TestCrackWorkerHashcatMode(t *testing.T) {
	tests := []struct {
		ht   HashType
		want string
	}{
		{HashKRB5TGS, "18200"},
		{HashKRB5ASREP, "18200"},
		{HashNTLM, "1000"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		if got := hashcatMode(tt.ht); got != tt.want {
			t.Errorf("hashcatMode(%s) = %q, want %q", tt.ht, got, tt.want)
		}
	}
}
