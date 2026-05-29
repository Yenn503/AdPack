package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	content := []byte("AdPack canary content for hashing")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	want := sha256Hex(content)
	if got != want {
		t.Errorf("hashFile() = %s, want %s", got, want)
	}
}

func TestHashFile_Missing(t *testing.T) {
	_, err := hashFile(filepath.Join(t.TempDir(), "does-not-exist.bin"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRandomizedName(t *testing.T) {
	name1 := randomizedName("payload.exe")
	name2 := randomizedName("payload.exe")

	if name1 == name2 {
		t.Errorf("randomizedName collisions: %s == %s (4 bytes ≈ 2^32, vanishingly unlikely)", name1, name2)
	}
	if !strings.HasPrefix(name1, "payload_") {
		t.Errorf("expected stem prefix in %s", name1)
	}
	if !strings.HasSuffix(name1, ".exe") {
		t.Errorf("expected .exe suffix in %s", name1)
	}
}

func TestRandomizedName_NoExtension(t *testing.T) {
	name := randomizedName("PhantomKiller")
	if strings.Contains(name, ".") {
		t.Errorf("unexpected extension introduced: %s", name)
	}
	if !strings.HasPrefix(name, "PhantomKiller_") {
		t.Errorf("expected stem prefix in %s", name)
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
