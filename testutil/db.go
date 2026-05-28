package testutil

import (
	"adpack/core"
	"adpack/storage"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TempDB creates a temporary SQLite database for integration testing.
func TempDB(t *testing.T) (*storage.DB, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "adpack-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	dbPath := filepath.Join(dir, "state.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("open test db: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.RemoveAll(dir)
	}

	return db, cleanup
}

// SeedState populates a test state with minimal valid data for smoke testing.
func SeedState(db *storage.DB) (*core.ADState, error) {
	if err := db.SaveHost(core.Host{IP: "192.168.56.10", Hostname: "DC01", Domain: "test.local", IsDC: true}); err != nil {
		return nil, fmt.Errorf("seed DC01: %w", err)
	}
	if err := db.SaveHost(core.Host{IP: "192.168.56.11", Hostname: "SRV01", Domain: "test.local", IsDC: false}); err != nil {
		return nil, fmt.Errorf("seed SRV01: %w", err)
	}
	if err := db.SaveCred(core.Credential{
		Type:      core.CredPlaintext,
		Username:  "Administrator",
		Domain:    "test.local",
		Secret:    "Password123!",
		Validated: true,
		Source:    "test",
	}); err != nil {
		return nil, fmt.Errorf("seed admin cred: %w", err)
	}

	state, err := db.LoadState()
	if err != nil {
		return nil, err
	}
	return state, nil
}
