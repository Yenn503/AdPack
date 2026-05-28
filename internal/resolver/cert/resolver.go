package cert

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"adpack/internal/resolver"
)

type CertResolver struct{}

func (r *CertResolver) Name() string { return "certipy" }

func (r *CertResolver) CanHandle(artifactType string) bool {
	return artifactType == "adcs.cert"
}

var certipySubjectCN = regexp.MustCompile(`Subject\s+CN=([^\s,]+)`)
var certipyUPN = regexp.MustCompile(`UPN=(\S+@\S+)`)
var certipyMachineAccount = regexp.MustCompile(`(?:Machine\s+)?Account[:\s]+(\S+\$)`)

func (r *CertResolver) Resolve(ctx context.Context, artifact resolver.ArtifactEvent) (*resolver.ResolvedArtifact, error) {
	if artifact.Path == "" {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, "certipy", "cert", "-pfx", artifact.Path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("certipy cert failed: %w", err)
	}

	outStr := string(output)
	ident := resolver.Identity{}

	if m := certipyMachineAccount.FindStringSubmatch(outStr); len(m) >= 2 {
		ident.Name = strings.TrimSpace(m[1])
	}
	if m := certipyUPN.FindStringSubmatch(outStr); len(m) >= 2 {
		ident.UPN = strings.TrimSpace(m[1])
		if parts := strings.SplitN(ident.UPN, "@", 2); len(parts) == 2 && ident.Name == "" {
			ident.Name = parts[0]
			ident.Domain = parts[1]
		}
	}
	if m := certipySubjectCN.FindStringSubmatch(outStr); len(m) >= 2 {
		ident.CertCN = strings.TrimSpace(m[1])
	}
	if ident.Domain == "" {
		if parts := strings.SplitN(ident.CertCN, ".", 2); len(parts) >= 2 {
			ident.Domain = strings.Join(parts[1:], ".")
		}
	}
	if ident.Name == "" || ident.Domain == "" {
		return nil, fmt.Errorf("cert resolver: could not extract identity from cert (name=%q domain=%q)", ident.Name, ident.Domain)
	}

	return &resolver.ResolvedArtifact{
		Type:       artifact.Type,
		Identity:   ident,
		Capability: "CERT_AUTH",
		Source:     "ESC8",
		Confidence: 0.85,
		Metadata: map[string]any{
			"cert_path": artifact.Path,
		},
	}, nil
}
