package modules

import (
	"testing"

	"adpack/core"
)

func TestCollectSilverTicketCandidates(t *testing.T) {
	state := core.NewADState()
	state.Users = []core.User{
		{Username: "mssql_svc", SAMAccountName: "mssql_svc", Domain: "DOM",
			SPNs: "MSSQLSvc/sql01.dom.local:1433,MSSQLSvc/sql01.dom.local"},
		{Username: "no_spn_user", SAMAccountName: "no_spn_user", Domain: "DOM"},
	}
	state.Creds = []core.Credential{
		// Machine account hash → derives cifs SPN.
		{Type: core.CredHash, Username: "DC01$", Domain: "DOM",
			Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Source: "secretsdump"},
		// Duplicate machine entry should be deduped.
		{Type: core.CredHash, Username: "DC01$", Domain: "DOM",
			Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Source: "secretsdump"},
		// Kerberoasted user with two SPNs → two candidates.
		{Type: core.CredHash, Username: "mssql_svc", Domain: "DOM",
			Hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Source: "kerberoast"},
		// User without SPNs in directory: skipped.
		{Type: core.CredHash, Username: "no_spn_user", Domain: "DOM",
			Hash: "cccccccccccccccccccccccccccccccc", Source: "spray"},
		// Plaintext password (not hash): skipped.
		{Type: core.CredPlaintext, Username: "alice", Domain: "DOM",
			Secret: "Passw0rd!"},
		// Empty hash: skipped.
		{Type: core.CredHash, Username: "x", Domain: "DOM", Hash: ""},
	}

	got := collectSilverTicketCandidates(state, "DOM")
	if len(got) != 3 {
		t.Fatalf("expected 3 candidates (1 machine + 2 kerberoasted SPNs), got %d: %+v", len(got), got)
	}

	var sawMachine, sawSPN1, sawSPN2 bool
	for _, c := range got {
		switch c.spn {
		case "cifs/dc01.dom":
			sawMachine = true
			if c.username != "DC01$" {
				t.Errorf("machine candidate has wrong username: %s", c.username)
			}
		case "MSSQLSvc/sql01.dom.local:1433":
			sawSPN1 = true
		case "MSSQLSvc/sql01.dom.local":
			sawSPN2 = true
		default:
			t.Errorf("unexpected SPN: %s", c.spn)
		}
		if c.hash == "" {
			t.Errorf("candidate missing hash: %+v", c)
		}
	}
	if !sawMachine {
		t.Error("missing expected cifs/dc01.dom candidate")
	}
	if !sawSPN1 || !sawSPN2 {
		t.Errorf("missing kerberoasted SPN candidates: spn1=%v spn2=%v", sawSPN1, sawSPN2)
	}
}

func TestExtractKrbtgtNTHash(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "standard secretsdump output",
			in: `[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5e7599e3a3a7feff7e8ec1f9c7a52a2d:::
[*] Cleaning up...`,
			want: "5e7599e3a3a7feff7e8ec1f9c7a52a2d",
		},
		{
			name: "uppercase hash gets lowercased",
			in:   "krbtgt:502:AAD3B435B51404EEAAD3B435B51404EE:ABCDEF1234567890ABCDEF1234567890:::",
			want: "abcdef1234567890abcdef1234567890",
		},
		{
			name: "no krbtgt line",
			in:   "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
			want: "",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
		{
			name: "krbtgt line not at start of line ignored",
			in:   "  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5e7599e3a3a7feff7e8ec1f9c7a52a2d:::",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKrbtgtNTHash(tt.in)
			if got != tt.want {
				t.Errorf("extractKrbtgtNTHash() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildAdminSDHolderDN(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"corp.local", "CN=AdminSDHolder,CN=System,DC=corp,DC=local"},
		{"north.sevenkingdoms.local", "CN=AdminSDHolder,CN=System,DC=north,DC=sevenkingdoms,DC=local"},
		{"single", "CN=AdminSDHolder,CN=System,DC=single"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := buildAdminSDHolderDN(tt.domain)
			if got != tt.want {
				t.Errorf("buildAdminSDHolderDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestBuildImpacketAuth(t *testing.T) {
	// Passwords with ':' or '@' break impacket's DOMAIN/user:pass@target parser
	// unless URL-encoded; this test locks in the encoding contract.
	tests := []struct {
		name                         string
		domain, user, pass, hash, dc string
		want                         string
	}{
		{
			name:   "simple password auth (no special chars)",
			domain: "corp.local", user: "admin", pass: "Passw0rd", hash: "", dc: "10.0.0.5",
			want: "corp.local/admin:Passw0rd@10.0.0.5",
		},
		{
			name:   "password with @ gets URL-encoded",
			domain: "corp.local", user: "admin", pass: "P@ss", hash: "", dc: "10.0.0.5",
			want: "corp.local/admin:P%40ss@10.0.0.5",
		},
		{
			name:   "password with : gets URL-encoded",
			domain: "corp.local", user: "admin", pass: "a:b", hash: "", dc: "10.0.0.5",
			want: "corp.local/admin:a%3Ab@10.0.0.5",
		},
		{
			name:   "hash-only auth omits password component",
			domain: "corp.local", user: "admin", pass: "", hash: "31d6cfe0d16ae931b73c59d7e0c089c0", dc: "10.0.0.5",
			want: "corp.local/admin@10.0.0.5",
		},
		{
			name:   "both pass and hash present prefers password form",
			domain: "corp.local", user: "admin", pass: "P@ss", hash: "deadbeef", dc: "10.0.0.5",
			want: "corp.local/admin:P%40ss@10.0.0.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildImpacketAuth(tt.domain, tt.user, tt.pass, tt.hash, tt.dc)
			if got != tt.want {
				t.Errorf("buildImpacketAuth() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestImpacketHashArgs(t *testing.T) {
	if got := impacketHashArgs(""); got != nil {
		t.Errorf("impacketHashArgs(\"\") = %v, want nil so callers can unconditionally append", got)
	}
	got := impacketHashArgs("deadbeef")
	want := []string{"-hashes", ":deadbeef"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("impacketHashArgs() = %v, want %v", got, want)
	}
}
