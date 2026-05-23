package bloodhound

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDirectory_RealOutput(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	if len(p.Users) == 0 {
		t.Error("expected at least 1 user")
	}
	if len(p.Groups) == 0 {
		t.Error("expected at least 1 group")
	}
	if len(p.Computers) == 0 {
		t.Error("expected at least 1 computer")
	}
	if len(p.Domains) == 0 {
		t.Error("expected at least 1 domain")
	}

	t.Logf("Parsed: %d users, %d groups, %d computers, %d domains",
		len(p.Users), len(p.Groups), len(p.Computers), len(p.Domains))

	// Verify known SIDs resolve
	sids := []string{
		"S-1-5-21-2392717932-3013346883-3168203123-500",  // Administrator
		"S-1-5-21-2392717932-3013346883-3168203123-512",  // Domain Admins
		"S-1-5-21-2392717932-3013346883-3168203123-1001", // KINGSLANDING$
	}
	for _, sid := range sids {
		if p.SIDMap[sid] == "" {
			t.Errorf("SID %s not found in SIDMap", sid)
		} else {
			t.Logf("  SID %s → %s (%s)", sid, p.SIDMap[sid], p.SIDToType[sid])
		}
	}

	// Verify group memberships
	daSID := "S-1-5-21-2392717932-3013346883-3168203123-512"
	for _, g := range p.Groups {
		if g.ObjectIdentifier == daSID {
			t.Logf("Domain Admins: %d direct members", len(g.Members))
			for _, m := range g.Members {
				t.Logf("  Member: %s (%s)", p.SIDMap[m.ObjectIdentifier], m.ObjectType)
			}
			if len(g.Members) == 0 {
				t.Error("Domain Admins has 0 members — group membership collection may be incomplete")
			}
			break
		}
	}
}

func TestParseDirectory_EmptyDir(t *testing.T) {
	dir, err := os.MkdirTemp("", "bh-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	p, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory(empty): %v", err)
	}
	if len(p.Users) != 0 || len(p.Groups) != 0 {
		t.Error("expected empty parse result")
	}
}

func TestParseDirectory_MissingFiles(t *testing.T) {
	// Only users file present
	dir, err := os.MkdirTemp("", "bh-partial-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Copy just the users file
	data, err := os.ReadFile(filepath.Join("testdata", "adpack_full_20260522020842_users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adpack_users.json"), data, 0644); err != nil {
		t.Fatalf("write adpack_users.json: %v", err)
	}

	p, err := ParseDirectory(dir)
	if err != nil {
		t.Fatalf("ParseDirectory(partial): %v", err)
	}
	if len(p.Users) == 0 {
		t.Error("expected users to be parsed")
	}
	if len(p.Groups) != 0 {
		t.Error("expected 0 groups when no groups file")
	}
}

func TestBHNameToPrincipal(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"LORD.VARYS@SEVENKINGDOMS.LOCAL", "sevenkingdoms\\lord.varys"},
		{"Administrator@sevenkingdoms.local", "sevenkingdoms\\administrator"},
		{"DOMAIN USERS@SEVENKINGDOMS.LOCAL", "sevenkingdoms\\domain users"},
		{"", ""},
		{"NOAT", "noat"},
	}
	for _, tt := range tests {
		got := bhNameToPrincipal(tt.input)
		if got != tt.expected {
			t.Errorf("bhNameToPrincipal(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestBHComputerToPrincipal(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"KINGSLANDING.SEVENKINGDOMS.LOCAL", "sevenkingdoms\\kingslanding$"},
		{"SRV02.sevenkingdoms.local", "sevenkingdoms\\srv02$"},
		{"", ""},
		{"NO_DOT", "no_dot$"},
	}
	for _, tt := range tests {
		got := bhComputerToPrincipal(tt.input)
		if got != tt.expected {
			t.Errorf("bhComputerToPrincipal(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseFiles_PopulatesSIDMap(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatal(err)
	}

	if len(p.SIDMap) == 0 {
		t.Fatal("SIDMap is empty")
	}

	// Every SID value should be non-empty
	for sid, name := range p.SIDMap {
		if name == "" {
			t.Errorf("SID %s maps to empty name", sid)
		}
	}

	// Every entry in SIDToType should be valid
	for sid, typ := range p.SIDToType {
		switch typ {
		case "User", "Group", "Computer", "Domain":
			// valid
		default:
			t.Errorf("SID %s has unknown type %q", sid, typ)
		}
		_ = sid
	}
}

func TestParseFile_BadJSON(t *testing.T) {
	p := &ParsedData{
		SIDMap:    make(map[string]string),
		SIDToType: make(map[string]string),
	}

	err := p.parseUsers([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}

func TestParseFile_EmptyJSONArray(t *testing.T) {
	p := &ParsedData{
		SIDMap:    make(map[string]string),
		SIDToType: make(map[string]string),
	}

	err := p.parseUsers([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Users) != 0 {
		t.Error("expected 0 users from empty data")
	}
}

func TestParseGroups_VerifyMemberFormat(t *testing.T) {
	p, err := ParseDirectory("testdata")
	if err != nil {
		t.Fatal(err)
	}

	// Domain Admins should have members with ObjectIdentifier and ObjectType
	var da *BHGroup
	for i, g := range p.Groups {
		if strings.Contains(g.Properties.Name, "DOMAIN ADMINS") {
			da = &p.Groups[i]
			break
		}
	}
	if da == nil {
		t.Skip("Domain Admins group not found in test data")
	}

	t.Logf("Domain Admins has %d members", len(da.Members))
	for _, m := range da.Members {
		if m.ObjectIdentifier == "" {
			t.Error("member has empty ObjectIdentifier")
		}
		if m.ObjectType != "User" && m.ObjectType != "Group" {
			t.Errorf("member %s has unexpected type %q", m.ObjectIdentifier, m.ObjectType)
		}
	}
}
