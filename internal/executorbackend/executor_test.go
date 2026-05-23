package executorbackend

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"adpack/core"
	"adpack/internal/executorbackend/addmember"
	"adpack/internal/executorbackend/asrep_roast"
	"adpack/internal/executorbackend/certauth"
	"adpack/internal/executorbackend/dcsync"
	"adpack/internal/executorbackend/forcechangepassword"
	"adpack/internal/executorbackend/genericall"
	"adpack/internal/executorbackend/kerberoast"
	"adpack/internal/executorbackend/ldap_spray"
	"adpack/internal/executorbackend/rbcd"
	"adpack/internal/executorbackend/shadowcred"
	"adpack/internal/executorbackend/writedacl"
)

func TestNewExecutor_ReturnsExecutor(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	if exec == nil {
		t.Fatal("New returned nil")
	}
}

func TestExecuteAction_UnknownMethod(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	res := exec.Execute(context.Background(), core.Action{
		Method:   "nonexistent",
		Artifact: "test",
		Timeout:  time.Second,
	})
	if res.Success {
		t.Fatal("expected failure for unknown method")
	}
	if res.Evidence == nil {
		t.Fatal("expected evidence entry for unknown method")
	}
	if res.Evidence.Kind != "unknown_method" {
		t.Fatalf("expected kind 'unknown_method', got %q", res.Evidence.Kind)
	}
}

func TestExecuteAction_CommandPopulatesEvidence(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	action := core.Action{
		Method:   "command",
		Artifact: "whoami",
		Timeout:  time.Second,
	}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	res := exec.Execute(context.Background(), action)

	if res.Evidence == nil {
		if res.Error == "" {
			t.Fatal("expected either error or evidence")
		}
		return
	}

	ev := res.Evidence
	if ev.Kind != "command_failover" {
		t.Fatalf("expected kind 'command_failover', got %q", ev.Kind)
	}
	if ev.Target != target {
		t.Fatal("evidence target mismatch")
	}
	if ev.Payload == nil {
		t.Fatal("evidence payload is nil")
	}

	var pl core.CommandPayload
	if err := json.Unmarshal(ev.Payload, &pl); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if pl.Command != "whoami" {
		t.Fatalf("expected command 'whoami', got %q", pl.Command)
	}
}

func TestExecuteAction_GetWithNoLocalPath(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	action := core.Action{
		Method:   "get",
		Artifact: "C:\\remote\\file.txt",
		Timeout:  time.Second,
	}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	res := exec.Execute(context.Background(), action)

	if res.Success {
		t.Fatal("expected failure for missing local path")
	}
	if res.Evidence == nil {
		t.Fatal("expected evidence even on failure")
	}

	ev := res.Evidence
	if ev.Kind != "file_get" {
		t.Fatalf("expected kind 'file_get', got %q", ev.Kind)
	}

	var pl core.FileOpPayload
	if err := json.Unmarshal(ev.Payload, &pl); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if pl.Operation != "get" {
		t.Fatalf("expected operation 'get', got %q", pl.Operation)
	}
	if pl.RemotePath != "C:\\remote\\file.txt" {
		t.Fatalf("expected remote path 'C:\\remote\\file.txt', got %q", pl.RemotePath)
	}
	if pl.Success {
		t.Fatal("expected success=false for failed get")
	}
}

func TestExecuteAction_CleanupPopulatesEvidence(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	action := core.Action{
		Method:   "cleanup",
		Artifact: "test.exe",
		Timeout:  time.Second,
	}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	res := exec.Execute(context.Background(), action)

	if res.Evidence == nil {
		t.Fatal("expected evidence entry for cleanup")
	}
	if res.Evidence.Kind != "cleanup" {
		t.Fatalf("expected kind 'cleanup', got %q", res.Evidence.Kind)
	}
}

// Invariant: every CapabilityRegistry executor MUST produce at least one
// edge on Execute. Non-graph-mutating actions (AV suppression, logging
// disruption) must NOT be registered as CapabilityExecutors — they go
// through the module-level evasion profile system instead.
func TestAllCapabilityExecutors_ProduceEdges(t *testing.T) {
	ctx := context.Background()
	state := &core.ADState{}

	tests := []struct {
		name     string
		executor core.CapabilityExecutor
		edge     core.PrivilegeEdge
	}{
		{
			name:     "GenericAll",
			executor: &genericall.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
			},
		},
		{
			name:     "CERT_AUTH",
			executor: &certauth.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				Domain:          "TEST",
				Requires:        []string{"certificate:CN=alice, Template=WebServer, CA=SEVENKINGDOMS-CA, UPN=alice@test.local"},
			},
		},
		{
			name:     "DCSync",
			executor: &dcsync.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				Domain:          "TEST",
				AccessRight:     "DCSync",
			},
		},
		{
			name:     "AddMember",
			executor: &addmember.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "domain admins",
				Domain:          "TEST",
				AccessRight:     "AddMember",
			},
		},
		{
			name:     "ForceChangePassword",
			executor: &forcechangepassword.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "ForceChangePassword",
			},
		},
		{
			name:     "WriteDACL",
			executor: &writedacl.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "WriteDacl",
			},
		},
		{
			name:     "RBCD",
			executor: &rbcd.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "DC01$",
				Domain:          "TEST",
				AccessRight:     "AllowedToActOnBehalfOfOtherIdentity",
			},
		},
		{
			name:     "SHADOW_CRED",
			executor: &shadowcred.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "KeyCredentialLink",
			},
		},
		{
			name:     "KERBEROAST",
			executor: &kerberoast.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "ServicePrincipalName",
			},
		},
		{
			name:     "ASREP_ROAST",
			executor: &asrep_roast.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "DontReqPreauth",
			},
		},
		{
			name:     "LDAP_SPRAY",
			executor: &ldap_spray.Executor{},
			edge: core.PrivilegeEdge{
				SourcePrincipal: "alice",
				TargetPrincipal: "bob",
				Domain:          "TEST",
				AccessRight:     "PasswordSpray",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.executor.CanExecute(ctx, tt.edge, state) {
				t.Fatal("CanExecute returned false — test edge is invalid")
			}
			result := tt.executor.Execute(ctx, tt.edge, state)
			if !result.Success() {
				t.Fatalf("Execute returned failure mode %v", result.FailureMode)
			}
			if len(result.Delta.NewEdges) == 0 {
				t.Fatal("Execute returned delta with 0 new edges — registry executors MUST produce at least one edge")
			}
		})
	}
}

func TestExecuteAction_EvidenceAlwaysPresent(t *testing.T) {
	target := core.HostRef{Name: "10.0.0.1", Domain: "TEST.LOCAL"}
	exec := New(target, "TEST.LOCAL", "admin", "pass", "")
	tests := []struct {
		method   string
		artifact string
		args     []string
		timeout  time.Duration
	}{
		{"nonexistent", "test", nil, time.Millisecond * 100},
		{"get", "", nil, time.Millisecond * 100},
	}
	for _, tt := range tests {
		res := exec.Execute(context.Background(), core.Action{
			Method: tt.method, Artifact: tt.artifact,
			Arguments: tt.args, Timeout: tt.timeout,
		})
		if res.Evidence == nil {
			t.Errorf("method %q: expected evidence, got nil", tt.method)
		}
	}
}
