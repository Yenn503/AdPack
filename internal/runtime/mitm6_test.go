package runtime

import "testing"

func TestParseMitm6Line(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		line        string
		wantKind    string
		wantSubject string
		wantValue   string
		wantOK      bool
	}{
		{
			name:        "spoofed reply",
			line:        "IPv6CP] Sent spoofed reply for fileserver.dom.local to fe80::dead:beef:cafe:1",
			wantKind:    "spoof",
			wantSubject: "fileserver.dom.local",
			wantValue:   "fe80::dead:beef:cafe:1",
			wantOK:      true,
		},
		{
			name:        "ipv6 assigned",
			line:        "[DHCPv6] IPv6 address fe80::1234:5678 is now assigned to victim01.dom.local",
			wantKind:    "assign",
			wantSubject: "victim01.dom.local",
			wantValue:   "fe80::1234:5678",
			wantOK:      true,
		},
		{
			name:        "got authentication",
			line:        "[ntlmrelayx] got authentication info for DOM\\\\administrator",
			wantKind:    "auth",
			wantSubject: "DOM\\\\administrator",
			wantOK:      true,
		},
		{
			name:   "ignored line",
			line:   "Starting mitm6 using the following configuration:",
			wantOK: false,
		},
		{
			name:   "empty",
			line:   "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, subject, value, ok := parseMitm6Line(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if kind != tc.wantKind {
				t.Errorf("kind = %q want %q", kind, tc.wantKind)
			}
			if subject != tc.wantSubject {
				t.Errorf("subject = %q want %q", subject, tc.wantSubject)
			}
			if value != tc.wantValue {
				t.Errorf("value = %q want %q", value, tc.wantValue)
			}
		})
	}
}

func TestBuildMitm6Args(t *testing.T) {
	t.Parallel()
	cfg := Mitm6Config{
		Interface:     "eth0",
		Domain:        "sevenkingdoms.local",
		HostAllowList: []string{"dc01.sevenkingdoms.local"},
		IgnoreNoFQDN:  true,
		Verbose:       true,
	}
	args := buildMitm6Args(cfg)

	want := map[string]bool{
		"-i":                       true,
		"eth0":                     true,
		"-d":                       true,
		"sevenkingdoms.local":      true,
		"--host-allowlist":         true,
		"dc01.sevenkingdoms.local": true,
		"--ignore-nofqdn":          true,
		"-v":                       true,
	}
	for _, a := range args {
		if !want[a] {
			continue // OK to have extra tokens; whitelist check below
		}
		delete(want, a)
	}
	if len(want) > 0 {
		t.Fatalf("missing args: %v (got %v)", want, args)
	}
}

func TestNewMitm6Service(t *testing.T) {
	t.Parallel()
	svc := NewMitm6Service("mitm6-test", "Test", Mitm6Config{
		Interface: "eth0", Domain: "dom.local",
	})
	if svc == nil {
		t.Fatal("NewMitm6Service returned nil")
	}
	if svc.ID != "mitm6-test" {
		t.Errorf("ID = %q want mitm6-test", svc.ID)
	}
	if svc.Type != "mitm6" {
		t.Errorf("Type = %q want mitm6", svc.Type)
	}
	if svc.Events == nil {
		t.Error("Events channel not initialised")
	}
	if svc.Config["interface"] != "eth0" {
		t.Errorf("interface config = %v want eth0", svc.Config["interface"])
	}
}
