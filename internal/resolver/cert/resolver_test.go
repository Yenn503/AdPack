package cert

import (
	"testing"
)

func TestCertipyRegex_MachineAccount(t *testing.T) {
	out := `Subject CN=KINGSLANDING.sevenkingdoms.local
UPN=HOST$@sevenkingdoms.local
Machine Account: KINGSLANDING$`
	m := certipyMachineAccount.FindStringSubmatch(out)
	if len(m) < 2 || m[1] != "KINGSLANDING$" {
		t.Fatalf("expected KINGSLANDING$, got %q", m[1])
	}
}

func TestCertipyRegex_UPN(t *testing.T) {
	out := `UPN=HOST$@sevenkingdoms.local`
	m := certipyUPN.FindStringSubmatch(out)
	if len(m) < 2 || m[1] != "HOST$@sevenkingdoms.local" {
		t.Fatalf("expected UPN match, got %q", m[1])
	}
}

func TestCertipyRegex_SubjectCN(t *testing.T) {
	out := `Subject CN=KINGSLANDING.sevenkingdoms.local`
	m := certipySubjectCN.FindStringSubmatch(out)
	if len(m) < 2 || m[1] != "KINGSLANDING.sevenkingdoms.local" {
		t.Fatalf("expected CN match, got %q", m[1])
	}
}
