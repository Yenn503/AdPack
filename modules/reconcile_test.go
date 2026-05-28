package modules

import (
	"testing"

	"adpack/core"
)

func TestReconcile_ExitCodeNonZero(t *testing.T) {
	v := ReconcileCrossCheck(core.ExecutionResult{}, core.Capability("ADD_MEMBER"), "", 1)
	if v.Trustworthy {
		t.Error("expected not trustworthy for non-zero exit")
	}
	if v.Confidence != 0.0 {
		t.Errorf("expected confidence 0, got %.2f", v.Confidence)
	}
}

func TestReconcile_EmptyOutput(t *testing.T) {
	v := ReconcileCrossCheck(core.ExecutionResult{}, core.Capability("ADD_MEMBER"), "", 0)
	if v.Trustworthy {
		t.Error("expected not trustworthy for empty output")
	}
}

func TestReconcile_AddMemberMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\Domain Admins",
				AccessRight:     "MemberOf",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("ADD_MEMBER"), "Group member added successfully", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
	v = ReconcileCrossCheck(predicted, core.Capability("ADD_MEMBER"), "Successfully added member to group", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy for variant, got: %s", v.Summary)
	}
}

func TestReconcile_AddMemberNoMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\Domain Admins",
				AccessRight:     "MemberOf",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("ADD_MEMBER"), "ERROR: access denied", 0)
	if v.Trustworthy {
		t.Fatalf("expected not trustworthy for error output")
	}
	if len(v.Mismatches) != 1 {
		t.Fatalf("expected exactly 1 mismatch, got %d", len(v.Mismatches))
	}
}

func TestReconcile_ForceChangePasswordMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\User",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("FORCE_CHANGE_PASSWORD"), "Password changed successfully", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
}

func TestReconcile_WriteDaclMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\Target",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("WRITE_DACL"), "Object ACL updated successfully", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
}

func TestReconcile_DCSyncMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\DC$",
				AccessRight:     "SIDHistory",
				EdgeType:        "dcsync",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("DCSYNC"),
		"[*] Dumping domain credentials (domain:sevenkingdoms.local)\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:8dCT-DJjgScp:::", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
}

func TestReconcile_CertAuthMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker$",
				TargetPrincipal: "sevenkingdoms.local\\DC01$",
				AccessRight:     "HasSession",
				EdgeType:        "cert",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("CERT_AUTH"), "Requested certificate successfully. Saved to 'dc01.pfx'", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
}

func TestReconcile_GenericAllMatch(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\Target",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("GENERIC_ALL"), "Delegated rights granted successfully", 0)
	if !v.Trustworthy {
		t.Fatalf("expected trustworthy, got: %s", v.Summary)
	}
}

func TestReconcile_OperationFailOutput(t *testing.T) {
	predicted := core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: "sevenkingdoms.local\\Attacker",
				TargetPrincipal: "sevenkingdoms.local\\User",
				AccessRight:     "GenericAll",
				EdgeType:        "acl",
			}},
		},
	}
	v := ReconcileCrossCheck(predicted, core.Capability("FORCE_CHANGE_PASSWORD"), "ERROR: insufficient access rights", 0)
	if v.Trustworthy {
		t.Fatalf("expected not trustworthy for error output")
	}
}

func TestReconcile_ZeroEdges(t *testing.T) {
	v := ReconcileCrossCheck(core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta:       core.PostStateDelta{},
	}, core.Capability("ADD_MEMBER"), "Group member added successfully", 0)
	if v.Trustworthy {
		t.Fatalf("expected not trustworthy for zero edges (invariant violation)")
	}
}
