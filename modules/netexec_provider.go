package modules

import (
	"context"
	"fmt"
	"time"

	"adpack/core"
	"adpack/tools"
)

// ProviderFromState extracts connection parameters from state and returns a
// NetExecProvider configured for the given target. Returns an error when no
// target or no credentials are available.
func ProviderFromState(state *core.ADState, targetHost string, sink core.ProviderEventSink) (core.DirectoryProvider, error) {
	host, found := selectTarget(state, targetHost)
	if !found {
		return nil, fmt.Errorf("no target available for graph analysis")
	}
	domain, user, pass, hash := getCredential(state)
	if domain == "" || user == "" {
		return nil, fmt.Errorf("no valid credentials for graph analysis")
	}
	return NewNetExecProvider(core.ProviderConfig{
		Host: host.IP, Domain: domain,
		Username: user, Password: pass, Hash: hash,
		EventSink: sink,
	}), nil
}

// NetExecProvider implements core.DirectoryProvider by routing requests through
// the NetExec CLI tool. This is the default (and currently only) provider, and
// exists so that a future LDAPProvider can be swapped in without changing the
// graph analysis orchestration.
type NetExecProvider struct {
	cfg core.ProviderConfig
}

func NewNetExecProvider(cfg core.ProviderConfig) *NetExecProvider {
	if cfg.EventSink == nil {
		cfg.EventSink = core.NoopSink{}
	}
	return &NetExecProvider{cfg: cfg}
}

func (p *NetExecProvider) ldapTarget() tools.NetExecTarget {
	return tools.NetExecTarget{
		Protocol: "ldap", Host: p.cfg.Host,
		Domain: p.cfg.Domain, Username: p.cfg.Username,
		Password: p.cfg.Password, Hash: p.cfg.Hash,
	}
}

func (p *NetExecProvider) mssqlTarget() tools.NetExecTarget {
	return tools.NetExecTarget{
		Protocol: "mssql", Host: p.cfg.Host, Port: 1433,
		Domain: p.cfg.Domain, Username: p.cfg.Username,
		Password: p.cfg.Password, Hash: p.cfg.Hash,
	}
}

func (p *NetExecProvider) smbTarget() tools.NetExecTarget {
	return tools.NetExecTarget{
		Protocol: "smb", Host: p.cfg.Host, Port: 445,
		Domain: p.cfg.Domain, Username: p.cfg.Username,
		Password: p.cfg.Password, Hash: p.cfg.Hash,
	}
}

func (p *NetExecProvider) emit(method, transport string, fallback bool, dur time.Duration, stdout, stderr string, exitCode int, count int, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	} else if exitCode != 0 {
		errStr = fmt.Sprintf("exit code %d", exitCode)
	}
	p.cfg.EventSink.Emit(core.ProviderEvent{
		Method: method, Transport: transport, Target: p.cfg.Host,
		Fallback: fallback, DurationMS: dur.Milliseconds(),
		StdoutBytes: len(stdout), StderrBytes: len(stderr),
		EntityCount: count, Error: errStr, Timestamp: time.Now(),
		Stdout: stdout, Stderr: stderr,
	})
}

func (p *NetExecProvider) EnumerateComputers(ctx context.Context) ([]core.Computer, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "--computers", nil)
	dur := time.Since(start)
	if err != nil || !r.Success {
		p.emit("EnumerateComputers", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		return nil, fmt.Errorf("nxc --computers: %w (stderr=%s)", err, r.Stderr)
	}
	computers := parseComputers(r.Stdout, p.cfg.Domain)
	p.emit("EnumerateComputers", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(computers), nil)
	return computers, nil
}

func (p *NetExecProvider) EnumerateGPOs(ctx context.Context) ([]core.GPO, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "--gpos", nil)
	dur := time.Since(start)

	if err == nil && r.Success {
		gpos := parseGPOs(r.Stdout, p.cfg.Domain)
		if len(gpos) > 0 {
			p.emit("EnumerateGPOs", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(gpos), nil)
			return gpos, nil
		}
	}

	// nxc --gpos returned empty or failed (removed in nxc v1.5.1+).
	// Fall back to ldapsearch for GPO enumeration.
	fmt.Println("[*] LDAP GPO listing empty, trying ldapsearch fallback...")
	start2 := time.Now()
	r2, err2 := tools.Ldapsearch.QueryGPOs(ctx, tools.LdapsearchConfig{
		Host: p.cfg.Host, Domain: p.cfg.Domain,
		Username: p.cfg.Username, Password: p.cfg.Password,
	})
	dur2 := time.Since(start2)
	totalDur := dur + dur2

	if err2 != nil {
		p.emit("EnumerateGPOs", "ldapsearch", true, totalDur, r2.Stdout, r2.Stderr, r2.ExitCode, 0, err2)
		return nil, fmt.Errorf("ldapsearch GPO query: %w", err2)
	}
	gpos := parseLDAPGPOs(r2.Stdout, p.cfg.Domain)
	if len(gpos) == 0 {
		p.emit("EnumerateGPOs", "ldapsearch", true, totalDur, r2.Stdout, r2.Stderr, 0, 0, nil)
		return gpos, nil
	}
	p.emit("EnumerateGPOs", "ldapsearch", true, totalDur, r2.Stdout, r2.Stderr, 0, len(gpos), nil)
	return gpos, nil
}

var sessionMethods = []struct {
	Flag      string
	Transport string
}{
	{"--loggedon-users", "smb+loggedon"},
	{"--reg-sessions", "smb+reg"},
	{"--qwinsta", "smb+qwinsta"},
}

func (p *NetExecProvider) EnumerateSessions(ctx context.Context) ([]core.Session, error) {
	host := core.Host{IP: p.cfg.Host}

	for i, m := range sessionMethods {
		start := time.Now()
		fallback := i > 0
		r, err := tools.NetExec.Run(ctx, p.smbTarget(), m.Flag, nil)
		dur := time.Since(start)

		if err == nil && r.Success {
			sessions := parseSMBSessions(host, r.Stdout)
			if len(sessions) > 0 {
				p.emit("EnumerateSessions", m.Transport, fallback, dur, r.Stdout, r.Stderr, 0, len(sessions), nil)
				return sessions, nil
			}
		}
		p.emit("EnumerateSessions", m.Transport, fallback, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
	}

	return nil, fmt.Errorf("all session enumeration methods failed (tried: --loggedon-users, --reg-sessions, --qwinsta)")
}

func (p *NetExecProvider) EnumerateAV(ctx context.Context) (map[string]string, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.smbTarget(), "-M", []string{"enum_av"})
	dur := time.Since(start)
	if err != nil || !r.Success {
		p.emit("EnumerateAV", "smb", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		return nil, fmt.Errorf("nxc enum_av: %w (stderr=%s)", err, r.Stderr)
	}
	av := parseEnumAV(r.Stdout)
	p.emit("EnumerateAV", "smb", false, dur, r.Stdout, r.Stderr, 0, len(av), nil)
	return av, nil
}

// highValueTargets returns principal names for daclread enumeration.
// These are the objects most likely to have exploitable ACEs.
func highValueTargets(state *core.ADState) []string {
	var targets []string
	seen := make(map[string]bool)

	for _, u := range state.Users {
		if u.IsDA {
			name := u.Username
			if !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}
	for _, g := range state.Groups {
		if g.Name == "Domain Admins" || g.Name == "Administrators" || g.Name == "Enterprise Admins" {
			if !seen[g.Name] {
				seen[g.Name] = true
				targets = append(targets, g.Name)
			}
		}
	}
	for _, c := range state.Computers {
		if c.IsDC {
			name := c.Name
			if !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}
	// AdminSDHolder is always a high-value target
	if !seen["AdminSDHolder"] {
		targets = append(targets, "AdminSDHolder")
	}
	return targets
}

// EnumerateACLs reads the DACL of a single target using nxc ldap -M daclread.
// Returns privilege edges for each non-system ACE found.
func (p *NetExecProvider) EnumerateACLs(ctx context.Context, targetName string) ([]core.PrivilegeEdge, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "-M", []string{"daclread", "-o", "ACTION=read", "-o", "TARGET=" + targetName})
	dur := time.Since(start)
	if err != nil || !r.Success {
		p.emit("EnumerateACLs", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		return nil, fmt.Errorf("nxc daclread target=%s: %w (stderr=%s)", targetName, err, r.Stderr)
	}
	edges := parseDaclReadACEs(r.Stdout, p.cfg.Domain, targetName)
	p.emit("EnumerateACLs", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(edges), nil)
	return edges, nil
}

// EnumerateMSSQLImpersonations checks for EXECUTE AS LOGIN permissions on
// MSSQL instances using nxc mssql -M mssql_priv. Returns privilege edges
// representing which logins can impersonate which targets.
func (p *NetExecProvider) EnumerateMSSQLImpersonations(ctx context.Context) ([]core.PrivilegeEdge, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.mssqlTarget(), "-M", []string{"mssql_priv"})
	dur := time.Since(start)
	if err != nil || !r.Success {
		p.emit("EnumerateMSSQLImpersonations", "mssql", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		return nil, fmt.Errorf("nxc mssql_priv: %w (stderr=%s)", err, r.Stderr)
	}
	edges := parseMSSQLImpersonations(r.Stdout, p.cfg.Domain, p.cfg.Host)
	p.emit("EnumerateMSSQLImpersonations", "mssql", false, dur, r.Stdout, r.Stderr, 0, len(edges), nil)
	return edges, nil
}

func (p *NetExecProvider) EnumerateADCSTemplates(ctx context.Context) ([]core.ADCSTemplate, error) {
	start := time.Now()
	r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "-M", []string{"certipy-find", "-o", "VULN=False", "ENABLED=False"})
	dur := time.Since(start)
	if err != nil || !r.Success {
		p.emit("EnumerateADCSTemplates", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		return nil, fmt.Errorf("nxc certipy-find: %w (stderr=%s)", err, r.Stderr)
	}
	templates := parseCertipyFind(r.Stdout, p.cfg.Domain)
	p.emit("EnumerateADCSTemplates", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(templates), nil)
	return templates, nil
}

func (p *NetExecProvider) EnumerateDelegation(ctx context.Context) ([]core.PrivilegeEdge, error) {
	var allEdges []core.PrivilegeEdge
	domain := p.cfg.Domain

	// 1. Unconstrained delegation
	{
		start := time.Now()
		r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "--trusted-for-delegation", nil)
		dur := time.Since(start)
		if err == nil && r.Success {
			edges := parseTrustedForDelegation(r.Stdout, domain)
			allEdges = append(allEdges, edges...)
			p.emit("EnumerateDelegation/trusted", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(edges), nil)
		} else {
			p.emit("EnumerateDelegation/trusted", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		}
	}

	// 2. Constrained delegation
	{
		start := time.Now()
		r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "--find-delegation", nil)
		dur := time.Since(start)
		if err == nil && r.Success {
			edges := parseConstrainedDelegation(r.Stdout, domain)
			allEdges = append(allEdges, edges...)
			p.emit("EnumerateDelegation/constrained", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(edges), nil)
		} else {
			p.emit("EnumerateDelegation/constrained", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		}
	}

	// 3. RBCD — custom LDAP query for AllowedToActOnBehalfOfOtherIdentity
	{
		start := time.Now()
		r, err := tools.NetExec.Run(ctx, p.ldapTarget(), "--query", []string{
			"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)", "dn", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		})
		dur := time.Since(start)
		if err == nil && r.Success {
			edges := parseRBCDelegation(r.Stdout, domain)
			allEdges = append(allEdges, edges...)
			p.emit("EnumerateDelegation/rbcd", "ldap", false, dur, r.Stdout, r.Stderr, 0, len(edges), nil)
		} else {
			p.emit("EnumerateDelegation/rbcd", "ldap", false, dur, r.Stdout, r.Stderr, r.ExitCode, 0, err)
		}
	}

	return allEdges, nil
}
