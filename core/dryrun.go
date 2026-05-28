package core

import "fmt"

type DryRunPlan struct {
	Phase       Phase
	Actions     []string
	Targets     []string
	Destructive bool
}

func DryRun(phase Phase, state *ADState) *DryRunPlan {
	plan := &DryRunPlan{
		Phase:   phase,
		Actions: []string{},
		Targets: []string{},
	}

	for _, h := range state.Hosts {
		plan.Targets = append(plan.Targets, h.IP)
	}

	switch phase {
	case PhaseDiscovery:
		plan.Actions = append(plan.Actions, "Run nmap discovery scan against configured subnets")
		plan.Actions = append(plan.Actions, "Identify live hosts, open ports, and OS fingerprints")
		plan.Actions = append(plan.Actions, "Mark discovered hosts for subsequent phases")
		plan.Destructive = false

	case PhaseEnumeration:
		plan.Actions = append(plan.Actions, "Enumerate users, groups, and computers via LDAP/SMB")
		plan.Actions = append(plan.Actions, "Extract domain metadata and trust relationships")
		if len(plan.Targets) > 0 {
			plan.Actions = append(plan.Actions, fmt.Sprintf("Query %d discovered hosts for session information", len(plan.Targets)))
		}
		plan.Destructive = false

	case PhaseCredentialAcq:
		plan.Actions = append(plan.Actions, "Attempt DCSync against domain controllers")
		plan.Actions = append(plan.Actions, "Run Kerberoasting against SPN-enabled accounts")
		plan.Actions = append(plan.Actions, "Run AS-REP roasting against pre-auth disabled accounts")
		plan.Actions = append(plan.Actions, "Scrape credentials from LDAP descriptions and SYSVOL")
		plan.Destructive = true

	case PhaseSessionHarvest:
		plan.Actions = append(plan.Actions, "Query hosts for active user sessions via SMB/NetSessionEnum")
		plan.Actions = append(plan.Actions, "Query hosts for logged-on users via NetWkstaUserEnum")
		plan.Actions = append(plan.Actions, "Correlate sessions with credential set for lateral movement targeting")
		plan.Destructive = false

	case PhaseGraphAnalysis:
		plan.Actions = append(plan.Actions, "Collect BloodHound data (bloodhound-python)")
		plan.Actions = append(plan.Actions, "Parse collector output for computers, GPOs, ADCS templates")
		plan.Actions = append(plan.Actions, "Reconcile collected data with existing state")
		plan.Destructive = false

	case PhaseLateral:
		plan.Actions = append(plan.Actions, "Execute lateral movement via WMI, WinRM, PsExec, or SchTasks")
		plan.Actions = append(plan.Actions, "Deploy C2 agent or beacon on target hosts")
		plan.Actions = append(plan.Actions, "Pivot through session chains to reach additional targets")
		plan.Destructive = true

	case PhaseValidation:
		plan.Actions = append(plan.Actions, "Validate acquired credentials against domain controllers")
		plan.Actions = append(plan.Actions, "Test credential reuse across discovered hosts")
		plan.Actions = append(plan.Actions, "Mark validated credentials for use in subsequent phases")
		plan.Destructive = false

	case PhasePrivEsc:
		plan.Actions = append(plan.Actions, "Analyze privilege edge graph for escalation paths")
		plan.Actions = append(plan.Actions, "Execute ACL-based attacks (GenericAll, WriteDACL, ForceChangePassword)")
		plan.Actions = append(plan.Actions, "Exploit ADCS templates (ESC1, ESC3, ESC8, Shadow Credentials)")
		plan.Actions = append(plan.Actions, "Perform Kerberos delegation abuse (S4U, RBCD, unconstrained)")
		plan.Destructive = true

	case PhasePersistence:
		plan.Actions = append(plan.Actions, "Create domain persistence mechanisms (Golden Ticket, Skeleton Key)")
		plan.Actions = append(plan.Actions, "Deploy scheduled tasks or services on domain controllers")
		plan.Actions = append(plan.Actions, "Add backdoor accounts or modify ACLs for persistence")
		plan.Destructive = true
	}

	return plan
}
