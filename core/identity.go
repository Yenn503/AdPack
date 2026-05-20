package core

import "strings"

// ResolveComputerRef produces the canonical HostRef from an LDAP-derived
// Computer entity. The name and domain are already split by the parser, so
// this is a pure projection.
func ResolveComputerRef(name, domain string) HostRef {
	return NewHostRef(name, domain)
}

// ResolveSessionRef extracts a HostRef from an SMB session username.
// Returns false when the username is not a machine account (no trailing $).
//
// Resolution rules:
//  1. DOMAIN\NAME$  → extract both directly
//  2. NAME$          → attach fallbackDomain
//  3. no trailing $  → not a machine account
func ResolveSessionRef(username string, fallbackDomain string) (HostRef, bool) {
	if username == "" || !strings.HasSuffix(username, "$") {
		return HostRef{}, false
	}

	// Strip trailing $; work with the remaining string to avoid slicing
	// mismatches between username and the trimmed copy.
	raw := strings.TrimSuffix(username, "$")

	if idx := strings.LastIndex(raw, "\\"); idx >= 0 {
		return NewHostRef(raw[idx+1:], raw[:idx]), true
	}
	if idx := strings.LastIndex(raw, "/"); idx >= 0 {
		return NewHostRef(raw[idx+1:], raw[:idx]), true
	}

	return NewHostRef(raw, fallbackDomain), true
}
