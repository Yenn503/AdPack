package resolver

import (
	"context"
	"time"
)

// ArtifactEvent describes a raw artifact discovered by a runtime service.
type ArtifactEvent struct {
	Type      string
	Stage     string
	Path      string
	SourceIP  string
	ServiceID string
	Timestamp time.Time
	Metadata  map[string]any
}

// Identity is a normalized representation of a resolved principal.
type Identity struct {
	Name   string // sAMAccountName (e.g. "KINGSLANDING$")
	Domain string // DNS domain (e.g. "sevenkingdoms.local")
	UPN    string // userPrincipalName if available
	CertCN string // certificate Subject CN for traceability
}

func (id Identity) String() string { return id.Name + "@" + id.Domain }

// ResolvedArtifact is the output of an ArtifactResolver.
type ResolvedArtifact struct {
	Type       string
	Identity   Identity
	Capability string
	Source     string
	Confidence float64
	Metadata   map[string]any
}

// ArtifactResolver can resolve a specific artifact type into an identity.
type ArtifactResolver interface {
	Name() string
	CanHandle(artifactType string) bool
	Resolve(ctx context.Context, artifact ArtifactEvent) (*ResolvedArtifact, error)
}
