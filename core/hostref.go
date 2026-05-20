package core

import "strings"

// HostRef is the canonical identity key for a single machine. Every
// observation surface (LDAP computer objects, SMB session hostnames,
// discovery hosts, GPO/ADCS context) must collapse to the same HostRef
// when referring to the same machine.
type HostRef struct {
	Name   string
	Domain string
}

// NewHostRef constructs a HostRef with normalised casing so that
// observations from different sources produce the same identity key.
func NewHostRef(name, domain string) HostRef {
	return HostRef{Name: strings.ToUpper(name), Domain: strings.ToUpper(domain)}
}
