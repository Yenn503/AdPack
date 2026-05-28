package modules

import (
	"testing"
)

func TestParseComputers_BareName(t *testing.T) {
	// nxc LDAP output where the computer name appears without a DOMAIN\ prefix
	output := `LDAP                     192.168.57.10   389    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:None) (channel binding:Never)
LDAP                     192.168.57.10   389    KINGSLANDING     [+] sevenkingdoms.local\Administrator:8dCT-DJjgScp (Pwn3d!)
LDAP                     192.168.57.10   389    KINGSLANDING     [*] Total records returned: 2
LDAP                     192.168.57.10   389    KINGSLANDING     KINGSLANDING$
LDAP                     192.168.57.10   389    KINGSLANDING     SRV02$`

	computers := parseComputers(output, "sevenkingdoms.local")
	if len(computers) != 2 {
		t.Fatalf("got %d computers, want 2", len(computers))
	}

	// Order matches appearance
	if computers[0].Name != "KINGSLANDING" || computers[0].Domain != "sevenkingdoms.local" {
		t.Errorf("computer[0]: got %s@%s, want KINGSLANDING@sevenkingdoms.local",
			computers[0].Name, computers[0].Domain)
	}
	// DC detection is line-local — the bare KINGSLANDING$ line doesn't
	// contain "server", so IsDC is false here. This is a known limitation
	// of the line-local heuristic.

	if computers[1].Name != "SRV02" || computers[1].Domain != "sevenkingdoms.local" {
		t.Errorf("computer[1]: got %s@%s, want SRV02@sevenkingdoms.local",
			computers[1].Name, computers[1].Domain)
	}
}

func TestParseComputers_FullyQualified(t *testing.T) {
	// nxc output with DOMAIN\COMPUTER$ format
	output := `SMB                      192.168.57.10   445    KINGSLANDING     [+] sevenkingdoms.local\Administrator (Pwn3d!)
SMB                      192.168.57.10   445    KINGSLANDING     sevenkingdoms.local\KINGSLANDING$
SMB                      192.168.57.11   445    NORTH           sevenkingdoms.local\NORTH-DC$`

	computers := parseComputers(output, "sevenkingdoms.local")
	if len(computers) != 2 {
		t.Fatalf("got %d computers, want 2", len(computers))
	}
	if computers[0].Name != "KINGSLANDING" || computers[0].Domain != "sevenkingdoms.local" {
		t.Errorf("computer[0]: got %s@%s, want KINGSLANDING@sevenkingdoms.local",
			computers[0].Name, computers[0].Domain)
	}
	if computers[1].Name != "NORTH-DC" || computers[1].Domain != "sevenkingdoms.local" {
		t.Errorf("computer[1]: got %s@%s, want NORTH-DC@sevenkingdoms.local",
			computers[1].Name, computers[1].Domain)
	}
}

func TestParseComputers_EmptyOutput(t *testing.T) {
	computers := parseComputers("", "domain.local")
	if len(computers) != 0 {
		t.Errorf("expected 0 computers from empty output, got %d", len(computers))
	}
}

func TestParseComputers_NoiseOnly(t *testing.T) {
	output := `---
|  header  |
SMB     something     [*] just a header`

	computers := parseComputers(output, "domain.local")
	if len(computers) != 0 {
		t.Errorf("expected 0 computers from noise-only output, got %d", len(computers))
	}
}

func TestParseComputers_NoComputerLines(t *testing.T) {
	// Lines with users but no trailing $ (should not match)
	output := `LDAP   192.168.57.10   389    DOMAIN     [+] domain.local\Administrator (Pwn3d!)
LDAP   192.168.57.10   389    DOMAIN     [*] Total records returned: 0`

	computers := parseComputers(output, "domain.local")
	if len(computers) != 0 {
		t.Errorf("expected 0 computers (no $ lines), got %d", len(computers))
	}
}

func TestParseComputers_Deduplicates(t *testing.T) {
	output := `LDAP   192.168.57.10   389    DOMAIN     KINGSLANDING$
LDAP   192.168.57.10   389    DOMAIN     KINGSLANDING$`

	computers := parseComputers(output, "sevenkingdoms.local")
	if len(computers) != 1 {
		t.Fatalf("expected 1 computer (deduplicated), got %d", len(computers))
	}
}

func TestParseLDAPGPOs_RealOutput(t *testing.T) {
	// Real ldapsearch output with ldif-wrap=no (no trailing dash-space wrapping).
	// GPOs from GOAD-Light: Default Domain Policy + Default Domain Controllers Policy.
	output := `dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=sevenkingdoms,DC=local
cn: {31B2F340-016D-11D2-945F-00C04FB984F9}
displayName: Default Domain Policy
gPCFileSysPath: \\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}

dn: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=sevenkingdoms,DC=local
cn: {6AC1786C-016F-11D2-945F-00C04fB984F9}
displayName: Default Domain Controllers Policy
gPCFileSysPath: \\sevenkingdoms.local\sysvol\sevenkingdoms.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
`

	gpos := parseLDAPGPOs(output, "sevenkingdoms.local")
	if len(gpos) != 2 {
		t.Fatalf("got %d GPOs, want 2", len(gpos))
	}

	if gpos[0].Name != "Default Domain Policy" || gpos[0].GUID != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Errorf("gpo[0]: got %s (%s), want Default Domain Policy ({31B2F340-016D-11D2-945F-00C04FB984F9})",
			gpos[0].Name, gpos[0].GUID)
	}
	if gpos[1].Name != "Default Domain Controllers Policy" || gpos[1].GUID != "{6AC1786C-016F-11D2-945F-00C04fB984F9}" {
		t.Errorf("gpo[1]: got %s (%s), want Default Domain Controllers Policy ({6AC1786C-016F-11D2-945F-00C04fB984F9})",
			gpos[1].Name, gpos[1].GUID)
	}
}

func TestParseLDAPGPOs_Deduplicates(t *testing.T) {
	output := `dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=domain,DC=local
cn: {31B2F340-016D-11D2-945F-00C04FB984F9}
displayName: Duplicate

dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=domain,DC=local
cn: {31B2F340-016D-11D2-945F-00C04FB984F9}
displayName: Duplicate
`

	gpos := parseLDAPGPOs(output, "domain.local")
	if len(gpos) != 1 {
		t.Fatalf("got %d GPOs, want 1 (deduplicated)", len(gpos))
	}
}

func TestParseLDAPGPOs_EmptyOutput(t *testing.T) {
	gpos := parseLDAPGPOs("", "domain.local")
	if len(gpos) != 0 {
		t.Errorf("expected 0 GPOs from empty output, got %d", len(gpos))
	}
}

func TestParseComputers_MixedFormats(t *testing.T) {
	// Mix of bare and fully-qualified
	output := `LDAP   192.168.57.10   389    DOMAIN     KINGSLANDING$
SMB    192.168.57.11   445    DOMAIN     other.domain.com\SRV02$`

	computers := parseComputers(output, "sevenkingdoms.local")
	if len(computers) != 2 {
		t.Fatalf("got %d computers, want 2", len(computers))
	}
	// Bare match uses domain parameter
	if computers[0].Domain != "sevenkingdoms.local" {
		t.Errorf("bare computer domain: got %s, want sevenkingdoms.local", computers[0].Domain)
	}
	// Fully-qualified uses extracted domain
	if computers[1].Domain != "other.domain.com" {
		t.Errorf("qualified computer domain: got %s, want other.domain.com", computers[1].Domain)
	}
}

func TestParseDaclReadACEs_RealOutput(t *testing.T) {
	input := `LDAP   192.168.57.10   389    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:None) (channel binding:Never)
LDAP   192.168.57.10   389    KINGSLANDING     [+] sevenkingdoms.local\Administrator:8dCT-DJjgScp (Pwn3d!)
DACLREAD 192.168.57.10   389    KINGSLANDING     Be careful, this module cannot read the DACLS recursively.
DACLREAD 192.168.57.10   389    KINGSLANDING     Target principal found in LDAP (CN=Domain Admins,CN=Users,DC=sevenkingdoms,DC=local)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[0] info
DACLREAD 192.168.57.10   389    KINGSLANDING        ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : ReadProperty
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[9] info
DACLREAD 192.168.57.10   389    KINGSLANDING        ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : ReadProperty, WriteProperty
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : Cert Publishers (S-1-5-21-2392717932-3013346883-3168203123-517)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[15] info
DACLREAD 192.168.57.10   389    KINGSLANDING        ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : ControlAccess
DACLREAD 192.168.57.10   389    KINGSLANDING        Object type (GUID)        : User-Change-Password (ab721a53-1e2f-11d0-9819-00aa0040529b)
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : Everyone (S-1-1-0)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[18] info
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : ReadAndExecute, ReadAndWrite, Read, Write, WriteDACL, ReadControl, WriteProperties, ListChildObjects, DeleteChild, CreateChild (0xe01bf)
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : Domain Admins (S-1-5-21-2392717932-3013346883-3168203123-512)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[19] info
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : ReadAndExecute, ReadAndWrite, Read, Write, WriteDACL, ReadControl, WriteProperties, ListChildObjects, DeleteChild, CreateChild (0xe01bf)
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : Enterprise Admins (S-1-5-21-2392717932-3013346883-3168203123-519)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[20] info
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : FullControl, Modify, ReadAndExecute, ReadAndWrite, Read, Write, WriteDACL, Delete, ListObject, WriteProperties, Self, CreateChild (0xf01ff)
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : lord.varys (S-1-5-21-2392717932-3013346883-3168203123-1121)
DACLREAD 192.168.57.10   389    KINGSLANDING     ACE[21] info
DACLREAD 192.168.57.10   389    KINGSLANDING        Access mask               : Modify, ReadAndExecute, ReadAndWrite, Read, Write, WriteDACL, ListObject, WriteProperties, Self (0xf01bf)
DACLREAD 192.168.57.10   389    KINGSLANDING        Trustee (SID)             : Administrators (S-1-5-32-544)
`
	edges := parseDaclReadACEs(input, "sevenkingdoms.local", "Domain Admins")

	// We expect:
	//   - ACE[0]: skipped (ReadProperty + BUILTIN trustee)
	//   - ACE[9]: Cert Publishers → WriteProperty → Domain Admins
	//   - ACE[15]: skipped (Everyone skip prefix)
	//   - ACE[18]: Domain Admins → WriteDacl → Domain Admins
	//   - ACE[19]: Enterprise Admins → WriteDacl → Domain Admins
	//   - ACE[20]: lord.varys → GenericAll → Domain Admins
	//   - ACE[21]: Administrators → WriteDacl → Domain Admins

	if len(edges) != 5 {
		t.Fatalf("got %d edges, want 5", len(edges))
	}

	// Build lookup map for assertions
	type edgeKey struct{ src, right, tgt string }
	got := make(map[edgeKey]bool)
	for _, e := range edges {
		got[edgeKey{e.SourcePrincipal, e.AccessRight, e.TargetPrincipal}] = true
	}

	cases := []struct {
		src, right, tgt string
	}{
		{"Cert Publishers", "WriteProperty", "Domain Admins"},
		{"Domain Admins", "WriteDacl", "Domain Admins"},
		{"Enterprise Admins", "WriteDacl", "Domain Admins"},
		{"lord.varys", "GenericAll", "Domain Admins"},
		{"Administrators", "WriteDacl", "Domain Admins"},
	}
	for _, c := range cases {
		if !got[edgeKey{c.src, c.right, c.tgt}] {
			t.Errorf("missing edge: %s → %s → %s", c.src, c.right, c.tgt)
		}
	}
}
