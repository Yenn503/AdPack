package modules

import (
	"path/filepath"
	"strings"
	"testing"

	"adpack/core"
)

func TestSecretsdumpNTDSExtractedRejectsCleanExitFailureText(t *testing.T) {
	output := `Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...`

	if secretsdumpNTDSExtracted(output) {
		t.Fatal("failed secretsdump output must not count as extracted NTDS hashes")
	}
}

func TestSecretsdumpNTDSExtractedAcceptsHashRows(t *testing.T) {
	output := `Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::`

	if !secretsdumpNTDSExtracted(output) {
		t.Fatal("valid secretsdump NTLM rows should count as extracted NTDS hashes")
	}
}

func TestSecretsdumpFailureSummaryPrefersActionableError(t *testing.T) {
	output := `Impacket v0.13.1
[*] Something routine
[-] RemoteOperations failed: SMB SessionError: code: 0xc000005e - STATUS_NO_LOGON_SERVERS - No logon servers are currently available to service the logon request.`

	got := secretsdumpFailureSummary(output)
	if !strings.Contains(got, "RemoteOperations failed") {
		t.Fatalf("expected actionable failure summary, got %q", got)
	}
}

func TestRunImpactFailsWhenNothingWasExfiltrated(t *testing.T) {
	oldLootDir := LootDir
	LootDir = filepath.Join(t.TempDir(), "loot")
	defer func() { LootDir = oldLootDir }()

	result := RunImpact(core.NewADState(), "native")
	if result.Success {
		t.Fatal("impact should fail when no NTDS, SYSVOL, share, or LSASS loot was exfiltrated")
	}
}
