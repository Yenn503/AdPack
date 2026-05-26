package storage

import (
	"path/filepath"
	"testing"

	"adpack/core"
)

// TestSaveCred_TrustPreservingUpsert encodes the invariant that a credential
// already marked Validated=true (e.g. seeded by the operator or returned by
// a network validation pass) MUST NOT be downgraded by a later, less-trusted
// upsert. Without this guarantee, an LDAP description scrape that captures a
// stale or malformed password silently overwrites the working credential and
// every downstream tool — impacket, nxc, bloodyAD, certipy — fails auth.
func TestSaveCred_TrustPreservingUpsert(t *testing.T) {
	t.Parallel()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	good := core.Credential{
		Type: core.CredPlaintext, Username: "samwell.tarly",
		Domain: "north.sevenkingdoms.local", Secret: "Heartsbane",
		Source: "manual_seed", Validated: true,
	}
	if err := db.SaveCred(good); err != nil {
		t.Fatalf("save validated cred: %v", err)
	}

	// Less-trusted scrape with a malformed value tries to overwrite.
	scraped := core.Credential{
		Type: core.CredPlaintext, Username: "samwell.tarly",
		Domain: "north.sevenkingdoms.local", Secret: "Heartsbane)",
		Source: "ldap_description", Validated: false,
	}
	if err := db.SaveCred(scraped); err != nil {
		t.Fatalf("save scraped cred: %v", err)
	}

	creds, err := db.LoadCreds()
	if err != nil {
		t.Fatalf("load creds: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	got := creds[0]
	if got.Secret != "Heartsbane" {
		t.Errorf("validated secret was overwritten: got %q want %q", got.Secret, "Heartsbane")
	}
	if !got.Validated {
		t.Error("validated flag was downgraded to false")
	}
	if got.Source != "manual_seed" {
		t.Errorf("source was downgraded: got %q want %q", got.Source, "manual_seed")
	}

	// A subsequent validated upsert from any source must win cleanly.
	upgraded := core.Credential{
		Type: core.CredPlaintext, Username: "samwell.tarly",
		Domain: "north.sevenkingdoms.local", Secret: "NewlyValidated!",
		Source: "validation_smb", Validated: true,
	}
	if err := db.SaveCred(upgraded); err != nil {
		t.Fatalf("save upgraded cred: %v", err)
	}
	creds, _ = db.LoadCreds()
	if len(creds) != 1 || creds[0].Secret != "NewlyValidated!" {
		t.Fatalf("validated upsert did not win, got %+v", creds)
	}
}
