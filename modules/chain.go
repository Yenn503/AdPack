package modules

import (
	"fmt"
	"strings"

	"adpack/core"
)

type ChainHint struct {
	FromEdge     core.PrivilegeEdge
	ToCapability core.Capability
	Description  string
	StepNumber   int
}

// ChainComposer scans the current edge set for sequential exploit
// opportunities and returns execution hints. This is a lookup table,
// not a planner — it detects known composite attack patterns such as:
//
//	RBCD + computer → delegation → DCSync
//	GenericAll/WriteDacl on DC → DCSync
//	Kerberoastable user → TGS hash → cracking
//	ShadowCredential → PKINIT auth → DCSync
func ChainComposer(state *core.ADState) []ChainHint {
	var hints []ChainHint

	for _, e := range state.Edges {
		right := strings.ToUpper(e.AccessRight)

		// RBCD chain: delegation → DCSync
		if strings.Contains(right, "ALLOWEDTOACT") || strings.EqualFold(e.EdgeType, "rbcd") {
			dcEdge := findTargetWithRight(state.Edges, e.TargetPrincipal, "DCSYNC")
			if dcEdge != nil {
				hints = append(hints, ChainHint{
					FromEdge: e, ToCapability: "DCSYNC",
					Description: fmt.Sprintf("RBCD on %s → DCSync possible via delegation chain", e.TargetPrincipal),
					StepNumber:  2,
				})
			} else {
				hints = append(hints, ChainHint{
					FromEdge: e, ToCapability: "DCSYNC",
					Description: fmt.Sprintf("RBCD on %s needs DCSync right to complete chain", e.TargetPrincipal),
					StepNumber:  1,
				})
			}
		}

		// GenericAll/WriteDacl on DC → DCSync
		if (strings.Contains(right, "GENERICALL") || strings.Contains(right, "WRITEDACL")) &&
			isDC(state, e.TargetPrincipal) {
			hints = append(hints, ChainHint{
				FromEdge: e, ToCapability: "DCSYNC",
				Description: fmt.Sprintf("ACL on %s allows DCSync grant", e.TargetPrincipal),
				StepNumber:  1,
			})
		}

		// GenericAll/WriteDacl on user → ShadowCred
		if strings.Contains(right, "GENERICALL") || strings.Contains(right, "WRITEDACL") {
			if !isDC(state, e.TargetPrincipal) {
				hints = append(hints, ChainHint{
					FromEdge: e, ToCapability: "SHADOW_CRED",
					Description: fmt.Sprintf("ACL on %s allows Shadow Credential abuse", e.TargetPrincipal),
					StepNumber:  1,
				})
			}
		}

		// Kerberoast edge → credential material
		if strings.EqualFold(e.EdgeType, "kerberoast") || strings.Contains(right, "SPN") {
			hints = append(hints, ChainHint{
				FromEdge: e, ToCapability: "KERBEROAST",
				Description: fmt.Sprintf("Request TGS for %s (SPN present)", e.TargetPrincipal),
				StepNumber:  1,
			})
		}

		// ShadowCred edge → PKINIT → DCSync
		if strings.EqualFold(e.EdgeType, "shadowcred") {
			dcEdge := findTargetWithRight(state.Edges, e.TargetPrincipal, "DCSYNC")
			if dcEdge != nil {
				hints = append(hints, ChainHint{
					FromEdge: e, ToCapability: "DCSYNC",
					Description: fmt.Sprintf("ShadowCred on %s → DCSync via PKINIT auth", e.TargetPrincipal),
					StepNumber:  2,
				})
			} else {
				hasSession := findEdgeToDC(state.Edges, e.SourcePrincipal)
				if hasSession != nil {
					hints = append(hints, ChainHint{
						FromEdge: e, ToCapability: "DCSYNC",
						Description: fmt.Sprintf("ShadowCred on %s needs DCSync on DC to complete", e.TargetPrincipal),
						StepNumber:  1,
					})
				}
			}
		}
	}

	return hints
}

func findTargetWithRight(edges []core.PrivilegeEdge, principal string, rightSubstring string) *core.PrivilegeEdge {
	for i, e := range edges {
		if strings.EqualFold(e.SourcePrincipal, principal) &&
			strings.Contains(strings.ToUpper(e.AccessRight), rightSubstring) {
			return &edges[i]
		}
	}
	return nil
}

func findEdgeToDC(edges []core.PrivilegeEdge, source string) *core.PrivilegeEdge {
	for i, e := range edges {
		if strings.EqualFold(e.SourcePrincipal, source) && isDCTarget(e.TargetPrincipal) {
			return &edges[i]
		}
	}
	return nil
}

// isDC checks if a principal is a domain controller by consulting
// the state's Computers list.
func isDC(state *core.ADState, principal string) bool {
	for _, c := range state.Computers {
		normalized := c.Domain + "\\" + c.Name + "$"
		if strings.EqualFold(normalized, principal) && c.IsDC {
			return true
		}
	}
	return isDCTarget(principal)
}

// isDCTarget is a fallback that matches common DC naming patterns.
func isDCTarget(principal string) bool {
	upper := strings.ToUpper(principal)
	return strings.HasSuffix(upper, "DC$") || strings.Contains(upper, "DC-") || strings.Contains(upper, "DC01")
}
