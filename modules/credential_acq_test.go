package modules

import (
	"testing"
)

func TestParseMimikatzOutput(t *testing.T) {
	output := `
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  *** Blog: https://blog.gentilkiwi.com/mimikatz
 ## \ / ##  *** Twitter: @gentilkiwi (Benjamin DELPY)
 '## v ##'  *** with 22 extensions
  '#####'   [22:20:30]
	
Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 5/18/2026 10:19:10 PM
SID               : S-1-5-19
	msv :	
	 tspkg :	
	 wdigest :	
	 * Username : LOCAL SERVICE
	 * Domain   : NT AUTHORITY
	 * Password : (null)
	 kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	
Authentication Id : 0 ; 12345 (00000000:00003039)
Session           : Interactive from 1
User Name         : Administrator
Domain            : vulnad.local
Logon Server      : DC1
Logon Time        : 5/18/2026 10:20:00 PM
SID               : S-1-5-21-1234567890-1234567890-1234567890-500
	msv :	
	 tspkg :	
	 wdigest :	
	 * Username : Administrator
	 * Domain   : vulnad.local
	 * Password : P@ssw0rd123!
`
	creds := parseMimikatzOutput(output)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Username != "Administrator" || creds[0].Domain != "vulnad.local" || creds[0].Secret != "P@ssw0rd123!" {
		t.Errorf("unexpected parsed credential: %+v", creds[0])
	}
}

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
