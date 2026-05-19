package tools

import (
	"adpack/utils"
	"context"
	"fmt"
	"strings"
)

type ldapTool struct{}

var LDAP = ldapTool{}

func (ldapTool) Name() string { return "ldapsearch" }

func (ldapTool) Available() bool { return utils.ToolAvailable("ldapsearch") }

func (ldapTool) Validate() error {
	if !utils.ToolAvailable("ldapsearch") {
		return &ToolError{Tool: "ldapsearch", Op: "Validate", Err: fmt.Errorf("not available")}
	}
	return nil
}

func (ldapTool) Capabilities() []Capability {
	return []Capability{CapLDAPQuery}
}

func (l ldapTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error) {
	ch := make(chan ExecutionEvent, 1)
	go func() {
		defer close(ch)
		result, err := l.Run(ctx, req)
		if err != nil {
			ch <- ExecutionEvent{Type: "error", Status: StatusFailed, Error: err}
			return
		}
		ch <- ExecutionEvent{Type: "complete", Status: StatusSuccess, Result: result}
	}()
	return ch, nil
}

func (l ldapTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	if len(req.Args) > 0 {
		switch req.Args[0] {
		case "users":
			return l.EnumUsers(ctx, req)
		case "dc":
			return l.EnumDomainControllers(ctx, req)
		}
	}
	return l.Query(ctx, req)
}

func (l ldapTool) Query(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	server := req.Target
	if server == "" && len(req.Args) > 0 {
		server = req.Args[0]
	}
	baseDN := ""
	if len(req.Args) > 1 {
		baseDN = req.Args[1]
	}
	query := ""
	if len(req.Args) > 2 {
		query = req.Args[2]
	}
	cr := utils.RunCommandCtx(ctx, "ldapsearch", []string{
		"-x", "-H", fmt.Sprintf("ldap://%s", server),
		"-b", baseDN, query,
	})
	return cmdResultToExecResult(cr), nil
}

func (l ldapTool) EnumUsers(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	server := req.Target
	if server == "" && len(req.Args) > 0 {
		server = req.Args[0]
	}
	domain := ""
	if len(req.Args) > 1 {
		domain = req.Args[1]
	}
	if domain == "" {
		domain = server
	}
	baseDN := fmt.Sprintf("DC=%s", strings.Replace(domain, ".", ",DC=", -1))
	cr := utils.RunCommandCtx(ctx, "ldapsearch", []string{
		"-x", "-H", fmt.Sprintf("ldap://%s", server),
		"-b", baseDN, "(objectClass=user)",
	})
	return cmdResultToExecResult(cr), nil
}

func (l ldapTool) EnumDomainControllers(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	server := req.Target
	if server == "" && len(req.Args) > 0 {
		server = req.Args[0]
	}
	domain := ""
	if len(req.Args) > 1 {
		domain = req.Args[1]
	}
	if domain == "" {
		domain = server
	}
	baseDN := fmt.Sprintf("DC=%s", strings.Replace(domain, ".", ",DC=", -1))
	cr := utils.RunCommandCtx(ctx, "ldapsearch", []string{
		"-x", "-H", fmt.Sprintf("ldap://%s", server),
		"-b", baseDN, "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
	})
	return cmdResultToExecResult(cr), nil
}
