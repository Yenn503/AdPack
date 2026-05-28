package core

import (
	"context"
	"testing"
)

func TestExecutionResult_Success(t *testing.T) {
	r := ExecutionResult{FailureMode: FailureSuccess}
	if !r.Success() {
		t.Fatal("expected Success() = true for FailureSuccess")
	}
}

func TestExecutionResult_NotSuccess(t *testing.T) {
	r := ExecutionResult{FailureMode: FailureRetryable}
	if r.Success() {
		t.Fatal("expected Success() = false for non-success failure mode")
	}
}

func TestCapabilityRegistry_Resolve(t *testing.T) {
	reg := NewCapabilityRegistry()
	_, status := reg.Resolve("non-existent")
	if status != CapabilityUnimplemented {
		t.Fatal("expected CapabilityUnimplemented for unregistered capability")
	}
}

type mockExecutor struct {
	cap Capability
}

func (m *mockExecutor) Capability() Capability { return m.cap }
func (m *mockExecutor) CanExecute(ctx context.Context, edge PrivilegeEdge, state *ADState) bool {
	return true
}
func (m *mockExecutor) Execute(ctx context.Context, edge PrivilegeEdge, state *ADState) ExecutionResult {
	return ExecutionResult{FailureMode: FailureSuccess}
}

func TestCapabilityRegistry_RegisterAndResolve(t *testing.T) {
	reg := NewCapabilityRegistry()
	exec := &mockExecutor{cap: "TEST_CAP"}
	reg.Register(exec)
	resolved, status := reg.Resolve("TEST_CAP")
	if status != CapabilityAvailable {
		t.Fatal("expected CapabilityAvailable for registered capability")
	}
	if resolved.Capability() != "TEST_CAP" {
		t.Fatalf("expected TEST_CAP, got %s", resolved.Capability())
	}
}

func TestApplyDelta_NewEdges(t *testing.T) {
	state := &ADState{}
	delta := PostStateDelta{
		NewEdges: []PrivilegeEdge{
			{SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
		},
	}
	before := state.Mutation.Version
	changed := ApplyDelta(state, delta)
	if !changed {
		t.Fatal("expected changed=true for new edges")
	}
	if len(state.Edges) != 1 {
		t.Fatalf("expected 1 edge after ApplyDelta, got %d", len(state.Edges))
	}
	if state.Mutation.Version != before+1 {
		t.Fatal("expected Version to increment after ApplyDelta")
	}
}

func TestApplyDelta_RemovedEdges(t *testing.T) {
	state := &ADState{
		Edges: []PrivilegeEdge{
			{SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
		},
	}
	delta := PostStateDelta{
		RemovedEdges: []EdgeKey{EdgeKeyOf(state.Edges[0])},
	}
	changed := ApplyDelta(state, delta)
	if !changed {
		t.Fatal("expected changed=true for edge removal")
	}
	if len(state.Edges) != 0 {
		t.Fatalf("expected 0 edges after removal, got %d", len(state.Edges))
	}
}

func TestApplyDelta_NoopDedup(t *testing.T) {
	state := &ADState{
		Edges: []PrivilegeEdge{
			{SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
		},
	}
	delta := PostStateDelta{
		NewEdges: []PrivilegeEdge{
			{SourcePrincipal: "a", TargetPrincipal: "b", AccessRight: "GenericAll", Domain: "TEST"},
		},
	}
	before := state.Mutation.Version
	changed := ApplyDelta(state, delta)
	if changed {
		t.Fatal("expected changed=false for duplicate edge")
	}
	if state.Mutation.Version != before {
		t.Fatal("expected Version unchanged for no-op delta")
	}
	if len(state.Edges) != 1 {
		t.Fatalf("expected 1 edge (no duplicates), got %d", len(state.Edges))
	}
}

func TestApplyDelta_NoopEmpty(t *testing.T) {
	state := &ADState{}
	delta := PostStateDelta{}
	before := state.Mutation.Version
	changed := ApplyDelta(state, delta)
	if changed {
		t.Fatal("expected changed=false for empty delta")
	}
	if state.Mutation.Version != before {
		t.Fatal("expected Version unchanged for empty delta")
	}
}

func TestAccessRightToCapability_Dispatch(t *testing.T) {
	tests := []struct {
		edge PrivilegeEdge
		want Capability
	}{
		{PrivilegeEdge{EdgeType: "cert"}, "CERT_AUTH"},
		{PrivilegeEdge{AccessRight: "DCSync"}, "DCSync"},
		{PrivilegeEdge{AccessRight: "AddMember"}, "ADD_MEMBER"},
		{PrivilegeEdge{AccessRight: "AddSelf"}, "ADD_MEMBER"},
		{PrivilegeEdge{AccessRight: "ForceChangePassword"}, "FORCE_CHANGE_PASSWORD"},
		{PrivilegeEdge{AccessRight: "WriteDacl"}, "WRITE_DACL"},
		{PrivilegeEdge{AccessRight: "WriteOwner"}, "WRITE_DACL"},
		{PrivilegeEdge{AccessRight: "MemberOf"}, "ADD_MEMBER"},
		{PrivilegeEdge{EdgeType: "dcsync"}, "DCSync"},
		{PrivilegeEdge{EdgeType: "rbcd"}, "RBCD"},
		{PrivilegeEdge{EdgeType: "shadowcred"}, "SHADOW_CRED"},
		{PrivilegeEdge{EdgeType: "kerberoast"}, "KERBEROAST"},
		{PrivilegeEdge{EdgeType: "asrep"}, "ASREP_ROAST"},
		{PrivilegeEdge{EdgeType: "spray"}, "LDAP_SPRAY"},
		{PrivilegeEdge{AccessRight: "HasSession", EdgeType: "mssql_impersonation"}, "MSSQL_XP_CMDSHELL"},
		{PrivilegeEdge{AccessRight: "GenericAll"}, "GenericAll"},
	}
	for _, tt := range tests {
		got := AccessRightToCapability(tt.edge)
		if got != tt.want {
			t.Errorf("AccessRightToCapability(%+v) = %s, want %s", tt.edge, got, tt.want)
		}
	}
}
