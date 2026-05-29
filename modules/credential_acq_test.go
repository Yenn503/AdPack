package modules

import (
	"testing"
)

func TestParseNanodumpOutput(t *testing.T) {
	output := `
[+] nanodump - version 1.0.0
[+] Opened lsass.exe PID: 688
[+] Forked lsass.exe PID: 1234
[+] Wrote minidump to /tmp/lsass.dmp

Parsing dump...
[+] System: Windows 10
[+] LSA version: 10.0

Username : Administrator
DomainName : vulnad.local
NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0

Username : user2
DomainName : vulnad.local
NTLM     : aabbccddeeff00112233445566778899
`
	creds := parseNanodumpOutput(output)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].Username != "Administrator" || creds[0].Hash != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Errorf("unexpected credential 0: %+v", creds[0])
	}
	if creds[1].Username != "user2" || creds[1].Hash != "aabbccddeeff00112233445566778899" {
		t.Errorf("unexpected credential 1: %+v", creds[1])
	}
}

func TestParseMalformedOutput(t *testing.T) {
	// Garbage input to ensure we don't panic
	output := "this is some garbage \n\n Username   \n DomainName : : \n NTLM: 123"
	creds := parseNanodumpOutput(output)
	if len(creds) != 0 {
		t.Fatalf("expected 0 credentials from malformed input, got %d", len(creds))
	}
}
