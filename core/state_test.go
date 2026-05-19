package core

import (
	"testing"
)

func TestDetectGaps_NoHosts(t *testing.T) {
	state := &ADState{
		Hosts: []Host{},
	}
	
	gaps := state.DetectGaps()
	
	found := false
	for _, gap := range gaps {
		if gap.Phase == PhaseDiscovery && gap.Message == "No hosts discovered" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No hosts discovered' gap to be detected")
	}
}

func TestDetectGaps_NoUsers(t *testing.T) {
	state := &ADState{
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{},
	}
	
	gaps := state.DetectGaps()
	
	found := false
	for _, gap := range gaps {
		if gap.Phase == PhaseEnumeration && gap.Message == "No users enumerated" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No users enumerated' gap to be detected")
	}
}

func TestDetectGaps_NoCreds(t *testing.T) {
	state := &ADState{
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{{Username: "admin"}},
		Creds: []Credential{},
	}
	
	gaps := state.DetectGaps()
	
	found := false
	for _, gap := range gaps {
		if gap.Phase == PhaseCredentialAcq && gap.Message == "No credentials acquired" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No credentials acquired' gap to be detected")
	}
}

func TestDetectGaps_NoValidatedCreds(t *testing.T) {
	state := &ADState{
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{{Username: "admin"}},
		Creds: []Credential{{Username: "admin", Validated: false}},
	}
	
	gaps := state.DetectGaps()
	
	found := false
	for _, gap := range gaps {
		if gap.Phase == PhaseValidation && gap.Message == "No credentials validated" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'No credentials validated' gap to be detected")
	}
}

func TestNextPhase_Discovery(t *testing.T) {
	state := &ADState{
		Phases: make(map[Phase]PhaseStatus),
		Hosts:  []Host{},
	}
	
	next := state.NextPhase()
	
	if next == nil {
		t.Fatal("NextPhase returned nil")
	}
	if *next != PhaseDiscovery {
		t.Errorf("Expected PhaseDiscovery, got %s", *next)
	}
}

func TestNextPhase_Enumeration(t *testing.T) {
	state := &ADState{
		Phases: map[Phase]PhaseStatus{
			PhaseDiscovery: PhaseComplete,
		},
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{},
	}
	
	next := state.NextPhase()
	
	if next == nil {
		t.Fatal("NextPhase returned nil")
	}
	if *next != PhaseEnumeration {
		t.Errorf("Expected PhaseEnumeration, got %s", *next)
	}
}

func TestNextPhase_CredentialAcq(t *testing.T) {
	state := &ADState{
		Phases: map[Phase]PhaseStatus{
			PhaseDiscovery:   PhaseComplete,
			PhaseEnumeration: PhaseComplete,
		},
		Hosts: []Host{{IP: "10.0.0.1"}},
		Users: []User{{Username: "admin"}},
		Creds: []Credential{},
	}
	
	next := state.NextPhase()
	
	if next == nil {
		t.Fatal("NextPhase returned nil")
	}
	if *next != PhaseCredentialAcq {
		t.Errorf("Expected PhaseCredentialAcq, got %s", *next)
	}
}

func TestNextPhase_AllComplete(t *testing.T) {
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
	}
	
	next := state.NextPhase()
	
	if next != nil {
		t.Errorf("Expected nil for complete state, got %s", *next)
	}
}

func TestPhaseDependencies(t *testing.T) {
	tests := []struct {
		phase Phase
		deps  []Phase
	}{
		{PhaseDiscovery, []Phase{}},
		{PhaseEnumeration, []Phase{PhaseDiscovery}},
		{PhaseCredentialAcq, []Phase{PhaseEnumeration}},
		{PhaseValidation, []Phase{PhaseCredentialAcq}},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.phase), func(t *testing.T) {
			deps := tt.phase.Dependencies()
			if len(deps) != len(tt.deps) {
				t.Errorf("Expected %d dependencies, got %d", len(tt.deps), len(deps))
			}
		})
	}
}
