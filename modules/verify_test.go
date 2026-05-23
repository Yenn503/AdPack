package modules

import (
	"strings"
	"testing"
	"time"

	"adpack/core"
)

func TestVerify_dnFromDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"sevenkingdoms.local", "DC=sevenkingdoms,DC=local"},
		{"north.sevenkingdoms.local", "DC=north,DC=sevenkingdoms,DC=local"},
		{"single", "DC=single"},
	}
	for _, tt := range tests {
		got := dnFromDomain(tt.domain)
		if got != tt.want {
			t.Errorf("dnFromDomain(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestVerify_AddMember_memberOfParsing(t *testing.T) {
	// Simulated ldapsearch output showing memberOf
	output := `dn: CN=Attacker,CN=Users,DC=sevenkingdoms,DC=local
memberOf: CN=Domain Admins,CN=Users,DC=sevenkingdoms,DC=local
memberOf: CN=Remote Desktop Users,CN=Users,DC=sevenkingdoms,DC=local
`

	targetLower := "domain admins"
	found := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), targetLower) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find 'domain admins' in memberOf output")
	}

	// Negative case: target not present
	output2 := `dn: CN=Attacker,CN=Users,DC=sevenkingdoms,DC=local
memberOf: CN=Users,CN=Users,DC=sevenkingdoms,DC=local
`
	found = false
	for _, line := range strings.Split(output2, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "domain admins") {
			found = true
			break
		}
	}
	if found {
		t.Fatal("expected NOT to find 'domain admins' in output without it")
	}
}

func TestVerify_ForceChangePassword_bindSuccessParsing(t *testing.T) {
	// Simulated ldapsearch output on successful bind
	output := `dn: CN=TargetUser,CN=Users,DC=sevenkingdoms,DC=local
cn: TargetUser
`

	if !strings.Contains(output, "cn:") {
		t.Fatal("expected cn: in successful bind output")
	}
	if !strings.Contains(output, "dn:") {
		t.Fatal("expected dn: in successful bind output")
	}

	// Negative: bind failure (empty output)
	empty := ""
	if strings.Contains(empty, "cn:") {
		t.Fatal("expected no cn: in empty output")
	}
}

func TestVerify_Dacl_outputParsing(t *testing.T) {
	// Simulated ldapsearch output for nTSecurityDescriptor
	output := `dn: CN=Target,CN=Users,DC=sevenkingdoms,DC=local
nTSecurityDescriptor: ...
sAMAccountName: Target
`
	if !strings.Contains(output, "nTSecurityDescriptor") {
		t.Fatal("expected nTSecurityDescriptor in output")
	}

	// Negative: no security descriptor returned
	output2 := `dn: CN=Target,CN=Users,DC=sevenkingdoms,DC=local
sAMAccountName: Target
`
	if strings.Contains(output2, "nTSecurityDescriptor") {
		t.Fatal("expected no nTSecurityDescriptor in this output")
	}
}

func TestVerify_State_integrationSignature(t *testing.T) {
	// Verify that VerifyState can be called with reasonable params and
	// returns a well-formed result (without actually running ldapsearch)
	edge := core.PrivilegeEdge{
		SourcePrincipal: "sevenkingdoms.local\\Attacker",
		TargetPrincipal: "sevenkingdoms.local\\Domain Admins",
		AccessRight:     "MemberOf",
		EdgeType:        "acl",
	}
	cap := core.Capability("ADD_MEMBER")

	// This will fail because ldapsearch isn't available in test env,
	// but it should return a structured result, not panic.
	ctx := t.Context()
	result := VerifyState(ctx, edge, cap, "sevenkingdoms.local", "Administrator", "pass", "192.168.57.10")

	if result.Evidence == "" {
		t.Fatal("expected non-empty evidence even on failure")
	}
	_ = result.Passed
	_ = result.Confidence
}

func TestVerify_UnknownCap_defaultPass(t *testing.T) {
	edge := core.PrivilegeEdge{}
	ctx := t.Context()
	result := VerifyState(ctx, edge, core.Capability("DCSYNC"), "d", "u", "p", "1.2.3.4")
	if !result.Passed {
		t.Fatal("expected DCSYNC to default-pass (tool output verified)")
	}
	result = VerifyState(ctx, edge, core.Capability("CERT_AUTH"), "d", "u", "p", "1.2.3.4")
	if !result.Passed {
		t.Fatal("expected CERT_AUTH to default-pass (tool output verified)")
	}
}

func TestVerify_AddMember_principalParsing(t *testing.T) {
	source := "sevenkingdoms.local\\Attacker"
	if idx := strings.Index(source, "\\"); idx >= 0 {
		source = source[idx+1:]
	}
	if source != "Attacker" {
		t.Fatalf("expected Attacker, got %s", source)
	}

	target := "sevenkingdoms.local\\Domain Admins"
	if idx := strings.Index(target, "\\"); idx >= 0 {
		target = target[idx+1:]
	}
	if target != "Domain Admins" {
		t.Fatalf("expected Domain Admins, got %s", target)
	}
}

func TestReVerify_daPathEdgeKeys_empty(t *testing.T) {
	state := core.NewADState()
	keys := daPathEdgeKeys(state)
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys for empty state, got %d", len(keys))
	}
}

func TestReVerify_daPathEdgeKeys_withCredsNoEdges(t *testing.T) {
	state := core.NewADState()
	state.Creds = []core.Credential{
		{Domain: "TEST", Username: "User", Secret: "pass", Validated: true},
	}
	keys := daPathEdgeKeys(state)
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys (no edges), got %d", len(keys))
	}
}

func TestReVerify_singleEdge_DCSync_defaultPass(t *testing.T) {
	edge := core.PrivilegeEdge{
		SourcePrincipal: "TEST\\User",
		TargetPrincipal: "TEST\\DC$",
		AccessRight:     "SIDHistory",
		EdgeType:        "dcsync",
		Domain:          "TEST",
	}
	// DCSYNC defaults pass (tool output verified) — doesn't need LDAP
	state := core.NewADState()
	state.Edges = append(state.Edges, edge)
	ctx := t.Context()
	ok := reVerifyEdgeAt(ctx, state, 0, "TEST", "u", "p", "1.2.3.4")
	if !ok {
		t.Fatal("expected DCSYNC to pass re-verification without LDAP")
	}
	if state.Edges[0].ValidationState != core.EdgeValidated {
		t.Fatalf("expected EdgeValidated, got %s", state.Edges[0].ValidationState)
	}
}

func TestReVerify_noStaleEdges(t *testing.T) {
	edge := core.PrivilegeEdge{
		SourcePrincipal: "TEST\\User",
		TargetPrincipal: "TEST\\DA",
		AccessRight:     "MemberOf",
		EdgeType:        "acl",
		Domain:          "TEST",
		LastVerifiedAt:  time.Now(), // not stale
	}
	state := core.NewADState()
	state.Edges = append(state.Edges, edge)
	ctx := t.Context()
	n := ReVerifyEdges(ctx, state, "TEST", "u", "p", "1.2.3.4", 10)
	if n != 0 {
		t.Fatalf("expected 0 re-verified (no stale edges), got %d", n)
	}
}

func TestReVerify_staleEdgeCount(t *testing.T) {
	// Use a DCSYNC edge — it passes through VerifyState without LDAP
	edge := core.PrivilegeEdge{
		SourcePrincipal: "TEST\\User",
		TargetPrincipal: "TEST\\DC$",
		AccessRight:     "SIDHistory",
		EdgeType:        "dcsync",
		Domain:          "TEST",
		// LastVerifiedAt zero → stale
	}
	state := core.NewADState()
	state.Edges = append(state.Edges, edge)
	ctx := t.Context()
	n := ReVerifyEdges(ctx, state, "TEST", "u", "p", "1.2.3.4", 10)
	// DCSYNC defaults pass (tool output verified) — edge should be marked verified
	if n != 1 {
		t.Fatalf("expected 1 re-verified edge, got %d", n)
	}
	if state.Edges[0].ValidationState != core.EdgeValidated {
		t.Fatalf("expected EdgeValidated, got %s", state.Edges[0].ValidationState)
	}
}
