package cracker

import (
	"sync"
	"testing"
	"time"
)

func TestMaterializerConsumesCrackComplete(t *testing.T) {
	q := NewHashQueue()
	var mu sync.Mutex
	var creds []CrackedCredential
	done := make(chan struct{})

	m := NewCredentialMaterializer(q, func(c CrackedCredential) {
		mu.Lock()
		creds = append(creds, c)
		mu.Unlock()
		close(done)
	})

	go m.Run()

	q.events <- CrackEvent{
		Type:   "crack_complete",
		Job:    &CrackJob{Username: "adm", Domain: "contoso", Hash: "hash123", HashType: HashNTLM},
		Result: "P@ssw0rd",
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for materializer to process event")
	}

	mu.Lock()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Secret != "P@ssw0rd" {
		t.Errorf("expected secret P@ssw0rd, got %s", creds[0].Secret)
	}
	if creds[0].Username != "adm" {
		t.Errorf("expected username adm, got %s", creds[0].Username)
	}
	if creds[0].Domain != "contoso" {
		t.Errorf("expected domain contoso, got %s", creds[0].Domain)
	}
	mu.Unlock()
}

func TestMaterializerSkipsEmptyResult(t *testing.T) {
	q := NewHashQueue()
	called := false
	m := NewCredentialMaterializer(q, func(c CrackedCredential) {
		called = true
	})

	go m.Run()

	q.events <- CrackEvent{
		Type:   "crack_complete",
		Job:    &CrackJob{Username: "u", Domain: "d", Hash: "h", HashType: HashNTLM},
		Result: "",
		Error:  nil,
	}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Error("materializer should not call callback when result is empty")
	}
}

func TestMaterializerSkipsNonCompleteEvents(t *testing.T) {
	q := NewHashQueue()
	called := false
	m := NewCredentialMaterializer(q, func(c CrackedCredential) {
		called = true
	})

	go m.Run()

	q.events <- CrackEvent{Type: "hash_enqueued", Job: &CrackJob{}}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Error("materializer should not call callback for non-complete events")
	}
}
