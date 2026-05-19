package core

import (
	"fmt"
)

type Recommendation struct {
	Phase      Phase    `json:"phase"`
	Strategies []string `json:"strategies"`
	Rationale  string   `json:"rationale"`
	Gaps       []Gap    `json:"gaps"`
}

type Engine struct{ State *ADState }

func NewEngine(s *ADState) *Engine { return &Engine{State: s} }

func (e *Engine) Evaluate() Recommendation {
	gaps := e.State.DetectGaps()
	nextPhase := e.State.NextPhase()
	rec := Recommendation{Gaps: gaps}

	if nextPhase == nil {
		rec.Rationale = "All phases complete or blocked. Review state."
		return rec
	}

	rec.Phase = *nextPhase

	rec.Strategies = PhaseStrategies(*nextPhase)
	switch *nextPhase {
	case PhaseDiscovery:
		rec.Rationale = "No hosts found. Run nmap sweep or specify targets."
	case PhaseEnumeration:
		rec.Rationale = fmt.Sprintf("Hosts=%d, Users=%d, Computers=%d. Enumerate AD objects via LDAP or NetExec.", len(e.State.Hosts), len(e.State.Users), len(e.State.Computers))
	case PhaseCredentialAcq:
		rec.Rationale = fmt.Sprintf("Users=%d, Creds=%d. Try Kerberoast, AS-REP, spray, LSASS.", len(e.State.Users), len(e.State.Creds))
	case PhaseSessionHarvest:
		rec.Rationale = "Validated creds but no sessions. Hunt sessions via NetExec SMB/LDAP."
	case PhaseGraphAnalysis:
		rec.Rationale = "Enumerated data collected. Run BloodHound for attack paths."
	case PhaseLateral:
		rec.Rationale = "Creds+sessions ready. Move laterally via WinRM/WMI/PSExec."
	case PhaseValidation:
		rec.Rationale = fmt.Sprintf("%d creds to validate. Test auth via SMB/LDAP/WinRM.", len(e.State.Creds))
	case PhasePrivEsc:
		rec.Rationale = "Check ACL abuse, ADCS, RBCD, GPP for privilege escalation."
	case PhasePersistence:
		rec.Rationale = "Establish persistence: krbtgt, DSRM, skeleton, admin SDHolder."
	}
	return rec
}

func PhaseStrategies(p Phase) []string {
	switch p {
	case PhaseDiscovery:
		return []string{"nmap_sweep", "ldap_ping", "dns_resolve"}
	case PhaseEnumeration:
		return []string{"ldap_user_enum", "ldap_computer_enum", "netexec_smb_enum", "netexec_ldap_enum"}
	case PhaseCredentialAcq:
		return []string{"kerberoast", "asrep_roast", "password_spray", "lsass_dump", "ntds_dump"}
	case PhaseSessionHarvest:
		return []string{"netexec_smb_sessions", "netexec_ldap_sessions", "bloodhound_sessions"}
	case PhaseGraphAnalysis:
		return []string{"bloodhound_collect", "bloodhound_ingest", "cypher_query"}
	case PhaseLateral:
		return []string{"psexec", "winrm", "wmi", "schtasks", "dcom"}
	case PhaseValidation:
		return []string{"netexec_smb_auth", "netexec_ldap_auth", "netexec_winrm_auth"}
	case PhasePrivEsc:
		return []string{"acl_analyze", "gpp_check", "adcs_abuse", "rbcd_check"}
	case PhasePersistence:
		return []string{"krbtgt_reset", "dsrm", "admin_sdholder", "silver_ticket"}
	}
	return nil
}
