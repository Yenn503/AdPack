package core

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	state := &ADState{
		Phases: make(map[Phase]PhaseStatus),
	}
	engine := NewEngine(state)
	
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.State != state {
		t.Error("Engine state not set correctly")
	}
}

func TestEvaluate_NoHosts(t *testing.T) {
	state := &ADState{
		Phases: make(map[Phase]PhaseStatus),
		Hosts:  []Host{},
	}
	engine := NewEngine(state)
	
	rec := engine.Evaluate()
	
	if rec.Phase != PhaseDiscovery {
		t.Errorf("Expected PhaseDiscovery, got %s", rec.Phase)
	}
	if len(rec.Gaps) == 0 {
		t.Error("Expected gaps to be detected")
	}
}

func TestEvaluate_HostsButNoUsers(t *testing.T) {
	state := &ADState{
		Phases: map[Phase]PhaseStatus{
			PhaseDiscovery: PhaseComplete,
		},
		Hosts: []Host{{IP: "10.0.0.1", IsDC: true}},
		Users: []User{},
	}
	engine := NewEngine(state)
	
	rec := engine.Evaluate()
	
	if rec.Phase != PhaseEnumeration {
		t.Errorf("Expected PhaseEnumeration, got %s", rec.Phase)
	}
}

func TestEvaluate_UsersButNoCreds(t *testing.T) {
	state := &ADState{
		Phases: map[Phase]PhaseStatus{
			PhaseDiscovery:   PhaseComplete,
			PhaseEnumeration: PhaseComplete,
		},
		Hosts: []Host{{IP: "10.0.0.1", IsDC: true}},
		Users: []User{{Username: "admin"}},
		Creds: []Credential{},
	}
	engine := NewEngine(state)
	
	rec := engine.Evaluate()
	
	if rec.Phase != PhaseCredentialAcq {
		t.Errorf("Expected PhaseCredentialAcq, got %s", rec.Phase)
	}
}

func TestEvaluate_AllComplete(t *testing.T) {
	state := &ADState{
		Phases: map[Phase]PhaseStatus{
			PhaseDiscovery:     PhaseComplete,
			PhaseEnumeration:   PhaseComplete,
			PhaseCredentialAcq: PhaseComplete,
			PhaseValidation:    PhaseComplete,
			PhaseSessionHarvest: PhaseComplete,
			PhaseGraphAnalysis: PhaseComplete,
			PhaseLateral:       PhaseComplete,
			PhasePrivEsc:       PhaseComplete,
			PhasePersistence:   PhaseComplete,
		},
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{{Username: "admin"}},
		Creds: []Credential{{Username: "admin"}},
	}
	engine := NewEngine(state)
	
	rec := engine.Evaluate()
	
	if rec.Phase != "" {
		t.Errorf("Expected empty phase for complete state, got %s", rec.Phase)
	}
}

func TestPhaseStrategies(t *testing.T) {
	tests := []struct {
		phase    Phase
		minCount int
	}{
		{PhaseDiscovery, 1},
		{PhaseEnumeration, 1},
		{PhaseCredentialAcq, 1},
		{PhaseValidation, 1},
		{PhaseSessionHarvest, 1},
		{PhaseGraphAnalysis, 1},
		{PhaseLateral, 1},
		{PhasePrivEsc, 1},
		{PhasePersistence, 1},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.phase), func(t *testing.T) {
			strategies := PhaseStrategies(tt.phase)
			if len(strategies) < tt.minCount {
				t.Errorf("Expected at least %d strategies, got %d", tt.minCount, len(strategies))
			}
		})
	}
}

func TestPhaseStrategies_UnknownPhase(t *testing.T) {
	strategies := PhaseStrategies("unknown_phase")
	if strategies != nil {
		t.Error("Expected nil for unknown phase")
	}
}
