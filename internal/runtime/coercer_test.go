package runtime

import (
	"strings"
	"testing"
)

func TestParseCoercerLine_Success(t *testing.T) {
	host, method, ok := parseCoercerLine("[*] SMB coercion triggered against KINGSLANDING at 2025-05-22 12:00:00")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "KINGSLANDING" {
		t.Fatalf("expected host=KINGSLANDING, got %q", host)
	}
	if method != "SMB" {
		t.Fatalf("expected method=SMB, got %q", method)
	}
}

func TestParseCoercerLine_FQDN(t *testing.T) {
	host, method, ok := parseCoercerLine("[*] coercion triggered against KINGSLANDING.SEVENKINGDOMS.LOCAL")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "KINGSLANDING.SEVENKINGDOMS.LOCAL" {
		t.Fatalf("expected host=KINGSLANDING.SEVENKINGDOMS.LOCAL, got %q", host)
	}
	if method != "" {
		t.Fatalf("expected empty method, got %q", method)
	}
}

func TestParseCoercerLine_WithDollar(t *testing.T) {
	host, method, ok := parseCoercerLine("[+] Successfully coerced KINGSLANDING$! Method: SMB")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "KINGSLANDING$" {
		t.Fatalf("expected host=KINGSLANDING$, got %q", host)
	}
	if method != "SMB" {
		t.Fatalf("expected method=SMB, got %q", method)
	}
}

func TestParseCoercerLine_CoercedFormat(t *testing.T) {
	host, method, ok := parseCoercerLine("[+] Coerced KINGSLANDING$ via SMB")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if host != "KINGSLANDING$" {
		t.Fatalf("expected host=KINGSLANDING$, got %q", host)
	}
	if method != "SMB" {
		t.Fatalf("expected method=SMB, got %q", method)
	}
}

func TestParseCoercerLine_Failed(t *testing.T) {
	_, _, ok := parseCoercerLine("[-] Failed to coerce TARGET via SMB")
	if ok {
		t.Fatal("expected ok=false for failed line")
	}
}

func TestParseCoercerLine_EmptyLine(t *testing.T) {
	_, _, ok := parseCoercerLine("")
	if ok {
		t.Fatal("expected ok=false for empty line")
	}
}

func TestBuildCoercerArgs_Basic(t *testing.T) {
	cfg := CoercerConfig{
		InterfaceIP: "10.0.0.5",
		Targets:     []string{"192.168.1.100"},
	}
	args := buildCoercerArgs(cfg)

	checkArg := func(name, value string) bool {
		for i, a := range args {
			if a == name && i+1 < len(args) && args[i+1] == value {
				return true
			}
		}
		return false
	}

	if !checkArg("-l", "10.0.0.5") {
		t.Error("missing -l 10.0.0.5")
	}
	if !checkArg("-t", "192.168.1.100") {
		t.Error("missing -t 192.168.1.100")
	}
	hasTimeout := false
	for _, a := range args {
		if a == "--timeout" {
			hasTimeout = true
			break
		}
	}
	if !hasTimeout {
		t.Error("missing --timeout")
	}
}

func TestParseCoercerLine_RealisticMultiLine(t *testing.T) {
	// Simulates typical impacket-coercer output against a lab DC
	output := `[*] Running impacket-coercer...
[*] SMB coercion triggered against KINGSLANDING at 2025-05-22 12:00:00
[*] HTTP coercion triggered against KINGSLANDING at 2025-05-22 12:00:01
[+] Successfully coerced KINGSLANDING$! Method: SMB
[+] Successfully coerced KINGSLANDING$! Method: HTTP
[*] Failed to coerce UNREACHABLE-HOST via SMB
[*] coercion triggered against KINGSLANDING.SEVENKINGDOMS.LOCAL
[+] Coerced KINGSLANDING$ via LDAP
[*] RPC coercion triggered against KINGSLANDING`

	lines := []struct {
		host, method string
		ok           bool
	}{
		{"", "", false}, // [*] Running impacket-coercer...
		{"KINGSLANDING", "SMB", true},
		{"KINGSLANDING", "HTTP", true},
		{"KINGSLANDING$", "SMB", true},
		{"KINGSLANDING$", "HTTP", true},
		{"", "", false}, // [*] Failed to coerce UNREACHABLE-HOST via SMB
		{"KINGSLANDING.SEVENKINGDOMS.LOCAL", "", true},
		{"KINGSLANDING$", "LDAP", true},
		{"KINGSLANDING", "RPC", true},
	}

	for i, line := range strings.Split(output, "\n") {
		if i >= len(lines) {
			break
		}
		host, method, ok := parseCoercerLine(line)
		if ok != lines[i].ok {
			t.Errorf("line %d: expected ok=%v, got %v (line=%q)", i, lines[i].ok, ok, line)
			continue
		}
		if ok {
			if host != lines[i].host {
				t.Errorf("line %d: expected host=%q, got %q", i, lines[i].host, host)
			}
			if method != lines[i].method {
				t.Errorf("line %d: expected method=%q, got %q", i, lines[i].method, method)
			}
		}
	}
}

func TestBuildCoercerArgs_WithMethods(t *testing.T) {
	cfg := CoercerConfig{
		InterfaceIP: "10.0.0.5",
		Targets:     []string{"192.168.1.100"},
		Methods:     []string{"smb", "http"},
	}
	args := buildCoercerArgs(cfg)

	checkMethod := func(method string) bool {
		for i, a := range args {
			if a == "-m" && i+1 < len(args) && args[i+1] == method {
				return true
			}
		}
		return false
	}

	if !checkMethod("smb") {
		t.Error("missing -m smb")
	}
	if !checkMethod("http") {
		t.Error("missing -m http")
	}
}
