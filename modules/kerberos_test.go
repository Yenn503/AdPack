package modules

import (
	"strings"
	"testing"

	"adpack/core"
)

func TestRoastHashCredentialStoresHashNotSecret(t *testing.T) {
	cred := roastHashCredential("brandon.stark", "north.sevenkingdoms.local", "$krb5asrep$23$brandon.stark@NORTH", "asrep_roast")

	if cred.Type != core.CredHash {
		t.Fatalf("expected hash credential type, got %s", cred.Type)
	}
	if cred.Hash == "" || !strings.HasPrefix(cred.Hash, "$krb5asrep$") {
		t.Fatalf("expected roast material in Hash, got %q", cred.Hash)
	}
	if cred.Secret != "" {
		t.Fatalf("expected Secret to remain empty for roast hash, got %q", cred.Secret)
	}
}
