package tools

import "testing"

func TestExecMethodOrder(t *testing.T) {
	// The failover order is operationally important: wmiexec first (stealth,
	// runs as auth user), then smbexec (service → SYSTEM, noisier), then
	// atexec (schtask → SYSTEM, last resort). Lock this in as a contract.
	want := []string{"wmiexec", "smbexec", "atexec"}
	if len(ExecMethodOrder) != len(want) {
		t.Fatalf("ExecMethodOrder len=%d, want %d", len(ExecMethodOrder), len(want))
	}
	for i, m := range want {
		if ExecMethodOrder[i] != m {
			t.Errorf("ExecMethodOrder[%d]=%q, want %q", i, ExecMethodOrder[i], m)
		}
	}
}
