package mssql

import (
	"context"
	"strings"

	"adpack/core"
)

type ImpersonateExecutor struct{}

func (e *ImpersonateExecutor) Capability() core.Capability {
	return "MSSQL_IMPERSONATE"
}

func (e *ImpersonateExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_EXECUTE_AS_LOGIN")
}

func (e *ImpersonateExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: "sa",
				AccessRight:     "MSSQL_SYSADMIN",
				EdgeType:        "mssql_impersonation",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.8,
			}},
		},
	}
}

type SysadminExecutor struct{}

func (e *SysadminExecutor) Capability() core.Capability {
	return "MSSQL_SYSADMIN"
}

func (e *SysadminExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_SYSADMIN")
}

func (e *SysadminExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "MSSQL_XP_CMDSHELL",
				EdgeType:        "mssql_xp_cmdshell",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.9,
			}},
		},
	}
}

type XPCMDShellExecutor struct{}

func (e *XPCMDShellExecutor) Capability() core.Capability {
	return "MSSQL_XP_CMDSHELL"
}

func (e *XPCMDShellExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_XP_CMDSHELL")
}

func (e *XPCMDShellExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: "SYSTEM@" + edge.TargetPrincipal,
				AccessRight:     "AdminTo",
				EdgeType:        "mssql_xp_cmdshell",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}

type UserImpersonateExecutor struct{}

func (e *UserImpersonateExecutor) Capability() core.Capability {
	return "MSSQL_EXECUTE_AS_USER"
}

func (e *UserImpersonateExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_EXECUTE_AS_USER")
}

func (e *UserImpersonateExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "MSSQL_SYSADMIN",
				EdgeType:        "mssql_impersonation",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.75,
			}},
		},
	}
}

type NTLMCoerceExecutor struct{}

func (e *NTLMCoerceExecutor) Capability() core.Capability {
	return "MSSQL_NTLM_COERCE"
}

func (e *NTLMCoerceExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_NTLM_COERCE")
}

func (e *NTLMCoerceExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "HasSession",
				EdgeType:        "ntlm_coerce",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}

type LinkedServerExecutor struct{}

func (e *LinkedServerExecutor) Capability() core.Capability {
	return "MSSQL_LINKED_SERVER"
}

func (e *LinkedServerExecutor) CanExecute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) bool {
	return strings.EqualFold(edge.AccessRight, "MSSQL_LINKED_SERVER")
}

func (e *LinkedServerExecutor) Execute(_ context.Context, edge core.PrivilegeEdge, _ *core.ADState) core.ExecutionResult {
	return core.ExecutionResult{
		FailureMode: core.FailureSuccess,
		Delta: core.PostStateDelta{
			NewEdges: []core.PrivilegeEdge{{
				SourcePrincipal: edge.SourcePrincipal,
				TargetPrincipal: edge.TargetPrincipal,
				AccessRight:     "MSSQL_XP_CMDSHELL",
				EdgeType:        "mssql_linked",
				Domain:          edge.Domain,
				Provenance:      "executor",
				Confidence:      0.7,
			}},
		},
	}
}
