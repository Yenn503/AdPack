package modules

import (
	"fmt"
	"strings"

	"adpack/core"
)

func isStealthPolicy(profile string) bool {
	if profile == "" {
		return false
	}
	base := BaseProfileFor(profile)
	return base == "stealth" || strings.Contains(strings.ToLower(profile), "stealth")
}

func edgeKey(e core.PrivilegeEdge) string {
	return e.Domain + "\x00" + e.SourcePrincipal + "\x00" + e.TargetPrincipal + "\x00" + e.AccessRight
}

func dedupEdges(newEdges []core.PrivilegeEdge, existing []core.PrivilegeEdge) []core.PrivilegeEdge {
	seen := make(map[string]bool, len(existing)+len(newEdges))
	for _, e := range existing {
		seen[edgeKey(e)] = true
	}
	var out []core.PrivilegeEdge
	for _, e := range newEdges {
		if !seen[edgeKey(e)] {
			seen[edgeKey(e)] = true
			out = append(out, e)
		}
	}
	return out
}

func drainRelayEdges(ch chan core.PrivilegeEdge) []core.PrivilegeEdge {
	var out []core.PrivilegeEdge
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e)
		default:
			return out
		}
	}
}

// materializeRelayEdge converts a ntlmrelayx capture into a privilege edge.
// Relay session captures get higher confidence (actual auth forwarded).
func materializeRelayEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
	if evt.Type != core.EvSessionCaptured && evt.Type != core.EvHashCaptured {
		return nil
	}

	raw, _ := evt.Data["raw"].(string)
	if raw == "" {
		return nil
	}

	accessRight := "RELAY_SESSION"
	confidence := 0.8
	exploitability := 0.85
	weight := 3.0
	if evt.Type == core.EvHashCaptured {
		accessRight = "RELAY_HASH"
		confidence = 0.6
		exploitability = 0.6
		weight = 4.0
	}

	sourceUser, _ := evt.Data["source_user"].(string)
	sourceDomain, _ := evt.Data["source_domain"].(string)
	if sourceUser == "" {
		return nil
	}
	sourcePrincipal := sourceDomain + "\\" + sourceUser

	targetDomain := sourceDomain
	if targetDomain == "" {
		targetDomain = "DOMAIN"
	}

	return &core.PrivilegeEdge{
		SourcePrincipal: sourcePrincipal,
		TargetPrincipal: targetDomain + "\\Domain Admins",
		AccessRight:     accessRight,
		EdgeType:        "relay",
		Domain:          targetDomain,
		Source:          "ntlmrelayx",
		Confidence:      confidence,
		Weight:          weight,
		Exploitability:  exploitability,
		Noise:           0.6,
		Requires:        []string{"impacket-ntlmrelayx", "impacket-secretsdump"},
		Preconditions: []core.ExecutionPrecondition{
			{Kind: core.PrecondPortOpen, Target: targetDomain, Port: 445, Description: "SMB for relay target"},
		},
	}
}

// materializeResponderEdge converts a Responder capture into a privilege edge.
// Responder hash captures are noisier and have lower confidence than relay sessions.
func materializeResponderEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
	if evt.Type != core.EvHashCaptured && evt.Type != core.EvSessionCaptured {
		return nil
	}

	raw, _ := evt.Data["raw"].(string)
	if raw == "" {
		return nil
	}

	captureMethod, _ := evt.Data["capture_method"].(string)
	if captureMethod == "poison" {
		// Poison notifications are informational, not credential captures
		return nil
	}

	accessRight := "RESPONDER_HASH"
	confidence := 0.5
	exploitability := 0.5
	weight := 5.0

	sourceUser, _ := evt.Data["source_user"].(string)
	sourceDomain, _ := evt.Data["source_domain"].(string)
	if sourceUser == "" {
		return nil
	}
	sourcePrincipal := sourceDomain + "\\" + sourceUser

	targetDomain := sourceDomain
	if targetDomain == "" {
		targetDomain = "DOMAIN"
	}

	return &core.PrivilegeEdge{
		SourcePrincipal: sourcePrincipal,
		TargetPrincipal: targetDomain + "\\Domain Admins",
		AccessRight:     accessRight,
		EdgeType:        "responder",
		Domain:          targetDomain,
		Source:          "responder",
		Confidence:      confidence,
		Weight:          weight,
		Exploitability:  exploitability,
		Noise:           0.8,
		Requires:        []string{"responder", "impacket-secretsdump"},
		Preconditions: []core.ExecutionPrecondition{
			{Kind: core.PrecondPortOpen, Target: targetDomain, Port: 445, Description: "SMB for pass-the-hash"},
		},
	}
}

// materializeCoercerEdge converts a Coercer event into a privilege edge.
// Coercer captures show that a target computer was coerced into authenticating
// to an attacker-controlled listener, which proves the target can reach us.
func materializeCoercerEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
	if evt.Type != core.EvCoerceSuccess && evt.Type != core.EvCoerceAttempt {
		return nil
	}

	host, _ := evt.Data["host"].(string)
	method, _ := evt.Data["method"].(string)
	target, _ := evt.Data["target"].(string)
	if host == "" {
		return nil
	}

	// Normalise hostname: strip FQDN → NetBIOS, append $, uppercase
	host = strings.SplitN(host, ".", 2)[0]
	if !strings.HasSuffix(host, "$") {
		host += "$"
	}
	host = strings.ToUpper(host)

	sourcePrincipal := host

	targetPrincipal := target

	accessRight := "COERCER_AUTH"
	if method != "" {
		accessRight = "COERCER_" + strings.ToUpper(method)
	}

	var confidence, weight, exploitability float64
	var edgeType string
	if evt.Type == core.EvCoerceSuccess {
		confidence = 0.8
		weight = 4.0
		exploitability = 0.7
		edgeType = "coercer_auth"
	} else {
		confidence = 0.4
		weight = 6.0
		exploitability = 0.5
		edgeType = "coercer_attempt"
	}

	domain := target
	if rawHost, _ := evt.Data["host"].(string); rawHost != "" {
		if parts := strings.SplitN(rawHost, ".", 2); len(parts) == 2 && parts[1] != "" {
			domain = parts[1]
		}
	}

	return &core.PrivilegeEdge{
		SourcePrincipal: sourcePrincipal,
		TargetPrincipal: targetPrincipal,
		AccessRight:     accessRight,
		EdgeType:        edgeType,
		Domain:          domain,
		Source:          "coercer",
		Confidence:      confidence,
		Weight:          weight,
		Exploitability:  exploitability,
		Noise:           0.5,
		Requires:        []string{"impacket-coercer", "responder", "impacket-ntlmrelayx"},
	}
}

// materializeResolverEdge converts a resolved artifact identity into a privilege edge.
// These edges represent external tool-based identity extraction (e.g. certipy parsing
// an ESC8 certificate capture) and feed directly into the planner graph.
func materializeResolverEdge(evt core.ServiceEvent) *core.PrivilegeEdge {
	identityName, _ := evt.Data["identity_name"].(string)
	identityDomain, _ := evt.Data["identity_domain"].(string)
	capability, _ := evt.Data["capability"].(string)
	confidence, _ := evt.Data["confidence"].(float64)
	if identityName == "" || identityDomain == "" {
		return nil
	}

	return &core.PrivilegeEdge{
		SourcePrincipal: identityName,
		TargetPrincipal: "DOMAIN ADMINS",
		AccessRight:     capability,
		EdgeType:        "resolved_identity",
		Domain:          identityDomain,
		Source:          evt.ServiceID,
		Confidence:      confidence,
		Weight:          2.0,
		Exploitability:  0.8,
		Noise:           0.3,
		Requires:        []string{"certipy"},
	}
}

// materializeEdgeFromEvent dispatches to the correct builder based on service type.
func materializeEdgeFromEvent(evt core.ServiceEvent) *core.PrivilegeEdge {
	switch evt.Service {
	case core.ServiceNTLMRelay:
		return materializeRelayEdge(evt)
	case core.ServiceResponder:
		return materializeResponderEdge(evt)
	case core.ServiceCoercion:
		return materializeCoercerEdge(evt)
	case core.ServiceResolver:
		return materializeResolverEdge(evt)
	default:
		return nil
	}
}

// runtimeHealthSummary returns a human-readable string describing active services.
func runtimeHealthSummary(runtime core.RuntimeProvider) string {
	svcs := runtime.Services()
	if len(svcs) == 0 {
		return "no services active"
	}
	var parts []string
	for _, svc := range svcs {
		state := "stopped"
		if svc.IsRunning() {
			state = "active"
		}
		hashCount := 0
		if cfg, ok := svc.Config["_hash_count"].(int); ok {
			hashCount = cfg
		}
		h := fmt.Sprintf("%s=%s", svc.Label, state)
		if hashCount > 0 {
			h += fmt.Sprintf("(%d hashes)", hashCount)
		}
		parts = append(parts, h)
	}
	return strings.Join(parts, " • ")
}
