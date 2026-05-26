package modules

import "testing"

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
		{"multiple users", "user1:1111:aad3:b4b4:::\nuser2:1112:aad3:4b4b:::", 2},
		{"duplicate hashes", "dup1:1111:aad3:b4b4:::\ndup2:1112:aad3:b4b4:::", 1},
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
