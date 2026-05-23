package bloodhound

import (
	"encoding/json"
	"strings"

	"adpack/core"
)

// Edge weight profiles for BloodHound-derived privilege edges.
// These are independent of the module-level edgeWeight table to avoid
// import cycles. Values are chosen to match the same semantics:
// lower weight = shorter path cost.

var bhEdgeWeight = map[string]struct {
	Weight         float64
	Exploitability float64
	Noise          float64
	Requires       []string
}{
	"GenericAll":          {6, 1.0, 0.7, []string{"nxc"}},
	"GenericWrite":        {7, 0.8, 0.6, []string{"nxc"}},
	"WriteDacl":           {7, 0.8, 0.7, []string{"nxc"}},
	"WriteOwner":          {7, 0.8, 0.6, []string{"nxc"}},
	"WriteProperty":       {8, 0.6, 0.5, nil},
	"ForceChangePassword": {5, 1.0, 0.9, []string{"nxc"}},
	"SelfMembership":      {6, 1.0, 0.8, []string{"nxc"}},
	"AddMember":           {6, 1.0, 0.8, []string{"nxc"}},
	"AllExtendedRights":   {5, 0.9, 0.7, nil},
	"MemberOf":            {1, 1.0, 0.0, nil},
	"AdminTo":             {3, 0.9, 0.6, []string{"nxc"}},
	"HasSession":          {4, 0.7, 0.3, nil},
	"AllowedToDelegate":   {5, 0.8, 0.6, []string{"impacket-getST"}},
}

func bhRightProfile(right string) (float64, float64, float64, []string) {
	if p, ok := bhEdgeWeight[right]; ok {
		return p.Weight, p.Exploitability, p.Noise, p.Requires
	}
	return 10, 0.5, 0.5, nil
}

// bhRightName maps BloodHound ACE RightName values to our canonical names.
func bhRightName(bhRight string) string {
	switch strings.TrimSpace(bhRight) {
	case "Owns":
		return "GenericAll"
	case "AllExtendedRights":
		return "AllExtendedRights"
	case "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl":
		return bhRight
	case "ForceChangePassword":
		return "ForceChangePassword"
	case "AddMember":
		return "AddMember"
	case "AddSelf":
		return "SelfMembership"
	case "WriteProperty":
		return "WriteProperty"
	case "ExtendedRight":
		return "AllExtendedRights"
	case "ReadProperty":
		return "" // skip read-only
	default:
		return bhRight
	}
}

// ConvertToState produces core.ADState from parsed BloodHound data.
func (p *ParsedData) ConvertToState(domain string) *core.ADState {
	state := &core.ADState{}

	// First pass: add users
	for _, u := range p.Users {
		principal := p.SIDMap[u.ObjectIdentifier]
		if principal == "" {
			continue
		}
		_, uname := splitPrincipal(principal)
		state.Users = append(state.Users, core.User{
			Username: uname,
			Domain:   domain,
			SID:      u.ObjectIdentifier,
			Enabled:  isEnabled(u.Properties.Enabled),
			Source:   "bloodhound",
		})
	}

	// Add groups
	for _, g := range p.Groups {
		principal := p.SIDMap[g.ObjectIdentifier]
		if principal == "" {
			continue
		}
		_, gname := splitPrincipal(principal)
		state.Groups = append(state.Groups, core.Group{
			Name:   gname,
			Domain: domain,
			SID:    g.ObjectIdentifier,
		})
	}

	// Add computers
	for _, c := range p.Computers {
		principal := p.SIDMap[c.ObjectIdentifier]
		if principal == "" {
			continue
		}
		_, cname := splitPrincipal(principal)
		state.Computers = append(state.Computers, core.Computer{
			Name:            strings.TrimSuffix(cname, "$"),
			Domain:          domain,
			SID:             c.ObjectIdentifier,
			OperatingSystem: c.Properties.OperatingSystem,
			IsDC:            c.Properties.IsDomainController,
		})
	}

	// Second pass: edges
	edges := p.convertEdges(state, domain)
	state.Edges = edges

	return state
}

// shortPrincipal returns just the account name from a SIDMap entry.
// SIDMap entries use "DOMAIN\name" format, but the planner expects only the
// name part with the Domain field carrying the domain separately.
func (p *ParsedData) shortPrincipal(sid string) string {
	principal := p.SIDMap[sid]
	if principal == "" {
		return ""
	}
	_, name := splitPrincipal(principal)
	return name
}

// convertEdges converts BloodHound relationships into PrivilegeEdges.
func (p *ParsedData) convertEdges(state *core.ADState, domain string) []core.PrivilegeEdge {
	var edges []core.PrivilegeEdge
	seen := make(map[string]bool)

	addEdge := func(src, tgt, right, etype string, conf float64, weight, exploit, noise float64, requires []string) {
		if src == "" || tgt == "" || right == "" {
			return
		}
		key := src + "|" + tgt + "|" + right
		if seen[key] {
			return
		}
		seen[key] = true
		edges = append(edges, core.PrivilegeEdge{
			SourcePrincipal: src,
			TargetPrincipal: tgt,
			AccessRight:     right,
			EdgeType:        etype,
			Domain:          domain,
			Source:          "bloodhound",
			Confidence:      conf,
			Weight:          weight,
			Exploitability:  exploit,
			Noise:           noise,
			Requires:        requires,
		})
	}

	// ── Group membership edges ────────────────────────────────
	for _, g := range p.Groups {
		tgtPrincipal := p.shortPrincipal(g.ObjectIdentifier)
		if tgtPrincipal == "" {
			continue
		}
		for _, m := range g.Members {
			srcPrincipal := p.shortPrincipal(m.ObjectIdentifier)
			if srcPrincipal == "" {
				continue
			}
			w, e, n, r := bhRightProfile("MemberOf")
			addEdge(srcPrincipal, tgtPrincipal, "MemberOf", "group_membership", 0.95, w, e, n, r)
		}
	}

	// ── ACL edges from all objects ────────────────────────────
	processACEs := func(targetSID string, aces []BHAce) {
		tgtPrincipal := p.shortPrincipal(targetSID)
		if tgtPrincipal == "" {
			return
		}
		for _, ace := range aces {
			srcPrincipal := p.shortPrincipal(ace.PrincipalSID)
			if srcPrincipal == "" {
				continue
			}
			right := bhRightName(ace.RightName)
			if right == "" {
				continue
			}
			w, e, n, r := bhRightProfile(right)
			addEdge(srcPrincipal, tgtPrincipal, right, "acl", 0.85, w, e, n, r)
		}
	}

	for _, u := range p.Users {
		processACEs(u.ObjectIdentifier, u.Aces)
	}
	for _, g := range p.Groups {
		processACEs(g.ObjectIdentifier, g.Aces)
	}
	for _, c := range p.Computers {
		processACEs(c.ObjectIdentifier, c.Aces)
	}
	for _, d := range p.Domains {
		processACEs(d.ObjectIdentifier, d.Aces)
	}

	// ── Local admin edges ─────────────────────────────────────
	for _, c := range p.Computers {
		tgtPrincipal := p.shortPrincipal(c.ObjectIdentifier)
		if tgtPrincipal == "" {
			continue
		}
		for _, raw := range c.LocalAdmins.Results {
			var la BHLocalAdminResult
			if err := json.Unmarshal(raw, &la); err != nil {
				continue
			}
			srcPrincipal := p.shortPrincipal(la.ObjectIdentifier)
			if srcPrincipal == "" {
				continue
			}
			w, e, n, r := bhRightProfile("AdminTo")
			addEdge(srcPrincipal, tgtPrincipal, "AdminTo", "local_admin", 0.85, w, e, n, r)
		}
	}

	// ── Session edges ─────────────────────────────────────────
	for _, c := range p.Computers {
		tgtPrincipal := p.shortPrincipal(c.ObjectIdentifier)
		if tgtPrincipal == "" {
			continue
		}
		for _, raw := range c.Sessions.Results {
			var s BHSessionResult
			if err := json.Unmarshal(raw, &s); err != nil {
				continue
			}
			srcPrincipal := p.shortPrincipal(s.UserSID)
			if srcPrincipal == "" {
				continue
			}
			w, e, n, r := bhRightProfile("HasSession")
			addEdge(srcPrincipal, tgtPrincipal, "HasSession", "session", 0.7, w, e, n, r)
		}
	}

	return edges
}

// isEnabled checks whether a BloodHound enabled value is truthy.
// It handles both bool and string representations.
func isEnabled(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true" || val == "True" || val == "TRUE" || val == "1"
	default:
		return false
	}
}

// splitPrincipal splits "DOMAIN\Name" into (domain, name).
func splitPrincipal(principal string) (string, string) {
	idx := strings.Index(principal, "\\")
	if idx < 0 {
		return "", principal
	}
	return principal[:idx], principal[idx+1:]
}
