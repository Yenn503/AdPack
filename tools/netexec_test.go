package tools

import "testing"

func TestExecMethodOrder(t *testing.T) {
	// atexec first (SYSTEM context via scheduled task, most reliable for
	// privileged ops like LSASS dump), then smbexec (service → SYSTEM),
	// then wmiexec (runs as auth user). Most AdPack operations require
	// SYSTEM so we prefer SYSTEM-capable methods first.
	want := []string{"atexec", "smbexec", "wmiexec"}
	if len(ExecMethodOrder) != len(want) {
		t.Fatalf("ExecMethodOrder len=%d, want %d", len(ExecMethodOrder), len(want))
	}
	for i, m := range want {
		if ExecMethodOrder[i] != m {
			t.Errorf("ExecMethodOrder[%d]=%q, want %q", i, ExecMethodOrder[i], m)
		}
	}
}
