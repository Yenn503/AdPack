package core

import (
	"encoding/json"
	"fmt"
	"time"
)

type ExecutionEvidence struct {
	Kind         string          `json:"kind"`
	Target       HostRef         `json:"target"`
	Action       Action          `json:"action"`
	Timestamp    time.Time       `json:"timestamp"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	MarshalError string          `json:"marshal_error,omitempty"`
}

var evidenceKinds = map[string]struct{}{
	"command_failover": {},
	"ldap_query":       {},
	"smb_command":      {},
	"file_put":         {},
	"file_get":         {},
	"cleanup":          {},
	"run_failover":     {},
	"system_check":     {},
	"unknown_method":   {},
}

func ValidEvidenceKind(kind string) error {
	if _, ok := evidenceKinds[kind]; !ok {
		return fmt.Errorf("unknown evidence kind %q", kind)
	}
	return nil
}

func newEvidence(kind string, target HostRef, action Action, payload any) ExecutionEvidence {
	if _, ok := evidenceKinds[kind]; !ok {
		panic(fmt.Sprintf("programming error: unknown evidence kind %q (must be registered in evidenceKinds)", kind))
	}
	raw, err := json.Marshal(payload)
	me := ""
	if err != nil {
		me = err.Error()
	}
	return ExecutionEvidence{
		Kind: kind, Target: target, Action: action,
		Timestamp: time.Now(), Payload: raw,
		MarshalError: me,
	}
}

func NewCommandFailoverEvidence(target HostRef, action Action, cmd, method, stdout, stderr string, exitCode int) ExecutionEvidence {
	return newEvidence("command_failover", target, action, CommandPayload{
		Command: cmd, Method: method, Stdout: stdout, Stderr: stderr, ExitCode: exitCode,
	})
}

func NewLdapQueryEvidence(target HostRef, action Action, query string, args []string, stdout, stderr string) ExecutionEvidence {
	return newEvidence("ldap_query", target, action, LdapPayload{
		Query: query, Arguments: args, Stdout: stdout, Stderr: stderr,
	})
}

func NewSmbCommandEvidence(target HostRef, action Action, subCmd string, args []string, stdout, stderr string) ExecutionEvidence {
	return newEvidence("smb_command", target, action, SmbPayload{
		SubCommand: subCmd, Arguments: args, Stdout: stdout, Stderr: stderr,
	})
}

func NewFilePutEvidence(target HostRef, action Action, remotePath string, success bool) ExecutionEvidence {
	return newEvidence("file_put", target, action, FileOpPayload{
		Operation: "put", RemotePath: remotePath, Success: success,
	})
}

func NewFileGetEvidence(target HostRef, action Action, remotePath, localPath string, success bool) ExecutionEvidence {
	return newEvidence("file_get", target, action, FileOpPayload{
		Operation: "get", RemotePath: remotePath, LocalPath: localPath, Success: success,
	})
}

func NewCleanupEvidence(target HostRef, action Action, success bool) ExecutionEvidence {
	return newEvidence("cleanup", target, action, FileOpPayload{
		Operation: "cleanup", Success: success,
	})
}

func NewRunFailoverEvidence(target HostRef, action Action, cmd, method, stdout, stderr string, exitCode int) ExecutionEvidence {
	return newEvidence("run_failover", target, action, CommandPayload{
		Command: cmd, Method: method, Stdout: stdout, Stderr: stderr, ExitCode: exitCode,
	})
}

func NewSystemCheckEvidence(target HostRef, action Action, method, stdout, stderr string, exitCode int) ExecutionEvidence {
	return newEvidence("system_check", target, action, CommandPayload{
		Command: "whoami", Method: method, Stdout: stdout, Stderr: stderr, ExitCode: exitCode,
	})
}

func NewSystemCheckFailedEvidence(target HostRef, action Action) ExecutionEvidence {
	return newEvidence("system_check", target, action, map[string]string{"result": "no_system_context"})
}

func NewUnknownMethodEvidence(target HostRef, action Action, cmd string) ExecutionEvidence {
	return newEvidence("unknown_method", target, action, CommandPayload{
		Command: cmd,
	})
}

type NetExecPayload struct {
	ExecMethod string   `json:"exec_method,omitempty"`
	Command    string   `json:"command,omitempty"`
	Arguments  []string `json:"arguments,omitempty"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	ExitCode   int      `json:"exit_code"`
}

type LdapPayload struct {
	Query     string   `json:"query"`
	Arguments []string `json:"arguments,omitempty"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
}

type SmbPayload struct {
	SubCommand string   `json:"sub_command,omitempty"`
	Arguments  []string `json:"arguments,omitempty"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
}

type FileOpPayload struct {
	Operation  string `json:"operation"`
	LocalPath  string `json:"local_path,omitempty"`
	RemotePath string `json:"remote_path,omitempty"`
	Success    bool   `json:"success"`
}

type CommandPayload struct {
	Command  string `json:"command"`
	Method   string `json:"method"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}
