package modules

import (
	"testing"
)

func TestParseComputers_MultiDomainIdentity(t *testing.T) {
	// Real nxc ldap --computers output from two DCs in a forest.
	// Both use bare COMPUTER$ format (no DOMAIN\ prefix).
	// This test validates that parseComputers assigns the correct domain
	// context to each host and keeps identities distinct across domains.

	domainA := "sevenkingdoms.local"
	domainB := "north.sevenkingdoms.local"

	ldapA := `LDAP   192.168.57.10   389    KINGSLANDING     [*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:None) (channel binding:Never)
LDAP   192.168.57.10   389    KINGSLANDING     [+] sevenkingdoms.local\Administrator:pass (Pwn3d!)
LDAP   192.168.57.10   389    KINGSLANDING     [*] Total records returned: 1
LDAP   192.168.57.10   389    KINGSLANDING     KINGSLANDING$`

	ldapB := `LDAP   192.168.57.11   389    WINTERFELL       [*] Windows 10 / Server 2019 Build 17763 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:None) (channel binding:No TLS cert)
LDAP   192.168.57.11   389    WINTERFELL       [+] north.sevenkingdoms.local\Administrator:pass (Pwn3d!)
LDAP   192.168.57.11   389    WINTERFELL       [*] Total records returned: 2
LDAP   192.168.57.11   389    WINTERFELL       WINTERFELL$
LDAP   192.168.57.11   389    WINTERFELL       CASTELBLACK$`

	hostsA := parseComputers(ldapA, domainA)
	hostsB := parseComputers(ldapB, domainB)

	// Domain A: should have 1 host
	if len(hostsA) != 1 {
		t.Fatalf("domain A: got %d hosts, want 1", len(hostsA))
	}
	if hostsA[0].Name != "KINGSLANDING" || hostsA[0].Domain != domainA {
		t.Errorf("domain A host: got %s@%s, want KINGSLANDING@%s",
			hostsA[0].Name, hostsA[0].Domain, domainA)
	}

	// Domain B: should have 2 hosts
	if len(hostsB) != 2 {
		t.Fatalf("domain B: got %d hosts, want 2", len(hostsB))
	}

	// Build identity map for overlap check
	hosts := append(hostsA, hostsB...)
	seen := make(map[string]bool)
	for _, h := range hosts {
		key := h.Name + "@" + h.Domain
		if seen[key] {
			t.Errorf("duplicate identity: %s", key)
		}
		seen[key] = true
	}

	// Verify specific identities exist
	expected := map[string]bool{
		"KINGSLANDING@sevenkingdoms.local":      true,
		"WINTERFELL@north.sevenkingdoms.local":  true,
		"CASTELBLACK@north.sevenkingdoms.local": true,
	}
	for _, h := range hosts {
		key := h.Name + "@" + h.Domain
		if !expected[key] {
			t.Errorf("unexpected identity: %s", key)
		}
		delete(expected, key)
	}
	for key := range expected {
		t.Errorf("missing identity: %s", key)
	}
}
