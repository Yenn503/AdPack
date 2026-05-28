package modules

import (
	"testing"

	"adpack/core"
)

func TestMarkOpenPortPersistsRuntimeAndHostPorts(t *testing.T) {
	state := &core.ADState{
		Hosts: []core.Host{
			{IP: "192.168.57.22", Hostname: "CASTELBLACK", PortsOpen: "445"},
		},
	}

	markOpenPort(state, "192.168.57.22", 1433)

	ports := state.Exec.OpenPorts["192.168.57.22"]
	if len(ports) != 1 || ports[0] != 1433 {
		t.Fatalf("expected runtime port 1433, got %#v", ports)
	}
	if got := state.Hosts[0].PortsOpen; got != "445,1433" {
		t.Fatalf("expected persisted host ports 445,1433, got %q", got)
	}
}

func TestMarkOpenPortDoesNotDuplicatePorts(t *testing.T) {
	state := &core.ADState{
		Hosts: []core.Host{
			{IP: "192.168.57.22", Hostname: "CASTELBLACK", PortsOpen: "1433,445"},
		},
		Exec: core.ExecutionState{OpenPorts: map[string][]int{"192.168.57.22": {1433}}},
	}

	markOpenPort(state, "192.168.57.22", 1433)

	if got := state.Hosts[0].PortsOpen; got != "1433,445" {
		t.Fatalf("expected host ports to remain unchanged, got %q", got)
	}
	ports := state.Exec.OpenPorts["192.168.57.22"]
	if len(ports) != 1 || ports[0] != 1433 {
		t.Fatalf("expected one runtime port, got %#v", ports)
	}
}

func TestRunPlanningUsesExistingEdges(t *testing.T) {
	state := &core.ADState{
		Hosts: []core.Host{
			{IP: "192.168.57.22", Hostname: "CASTELBLACK", PortsOpen: "445,1433"},
		},
		Creds: []core.Credential{
			{Domain: "north.sevenkingdoms.local", Username: "samwell.tarly", Secret: "Heartsbane", Validated: true},
		},
		Edges: []core.PrivilegeEdge{
			{
				SourcePrincipal: "samwell.tarly",
				TargetPrincipal: "SYSTEM@192.168.57.22",
				AccessRight:     "MSSQL_XP_CMDSHELL",
				EdgeType:        "mssql_impersonation",
				Domain:          "north.sevenkingdoms.local",
				Confidence:      0.9,
				Weight:          2,
				Exploitability:  1.0,
				Noise:           0.6,
				Requires:        []string{"nxc"},
				Preconditions: []core.ExecutionPrecondition{
					{Kind: core.PrecondPortOpen, Target: "192.168.57.22", Port: 1433},
				},
			},
		},
	}
	result := &core.ToolResult{Success: true}

	plans := runPlanning(state, result, []string{"nxc"})

	if len(plans) != 1 {
		t.Fatalf("expected one plan from existing state edge, got %d", len(plans))
	}
	if _, ok := plans["north.sevenkingdoms.local\\SYSTEM@192.168.57.22"]; !ok {
		t.Fatalf("expected plan to MSSQL SYSTEM target, got %#v", plans)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("expected planner evidence for existing edge")
	}
}
