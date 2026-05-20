package tools

import (
	"context"
	"sync"
	"time"
)

type Capability string

const (
	CapLSASSDump    Capability = "credential.lsass.dump"
	CapEDRBypass    Capability = "evasion.edr.bypass"
	CapDefenderKill Capability = "evasion.defender.kill"
	CapKerberos     Capability = "kerberos.roast"
	CapDCSync       Capability = "credential.dcsync"
	CapSMBExec      Capability = "execution.smb"
	CapWinRMExec    Capability = "execution.winrm"
	CapLDAPQuery    Capability = "ldap.query"
	CapShellcodeGen Capability = "payload.shellcode"
	CapSyscallGen   Capability = "evasion.syscall"
	CapDonut        Capability = "payload.donut"
	CapEDRKill      Capability = "evasion.edr.kill"
	CapPrivEsc      Capability = "privilege.escalation"
	CapNetExec      Capability = "execution.netexec"
	CapFileTransfer Capability = "execution.filetransfer"
)

type ExecutionStatus string

const (
	StatusQueued    ExecutionStatus = "queued"
	StatusRunning   ExecutionStatus = "running"
	StatusSuccess   ExecutionStatus = "success"
	StatusFailed    ExecutionStatus = "failed"
	StatusCancelled ExecutionStatus = "cancelled"
	StatusTimeout   ExecutionStatus = "timeout"
	StatusRetrying  ExecutionStatus = "retrying"
)

type ExecutionRequest struct {
	CampaignID    string
	ExecutionID   string
	CorrelationID string
	TraceID       string
	Target        string
	Credentials   *Credential
	Timeout       time.Duration
	Evasion       string
	WorkingDir    string
	Env           map[string]string
	Args          []string
	EvidenceID    string
	ParentEventID string
}

type Credential struct {
	Username string
	Password string
	Domain   string
	Hash     string
	LMHash   string
	NTHash   string
}

type ExecutionResult struct {
	Status        ExecutionStatus
	Stdout        string
	Stderr        string
	ExitCode      int
	Success       bool
	Duration      time.Duration
	CorrelationID string
	Artifacts     []Artifact
	Telemetry     []TelemetryEvent
}

type Artifact struct {
	Path     string
	MIMEType string
	Size     int64
	Hash     string
}

type TelemetryEvent struct {
	Module     string
	Duration   time.Duration
	Success    bool
	Host       string
	OPSECScore int
	NoiseLevel int
}

type ExecutionEvent struct {
	Type      string
	Status    ExecutionStatus
	Source    string
	Timestamp time.Time
	Result    *ExecutionResult
	Error     error
}

type Tool interface {
	Name() string
	Available() bool
	Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error)
	RunStream(ctx context.Context, req ExecutionRequest) (<-chan ExecutionEvent, error)
	Validate() error
	Capabilities() []Capability
}

type Executor interface {
	Execute(ctx context.Context, req ExecCommandRequest) (*ExecutionResult, error)
	ExecuteStream(ctx context.Context, req ExecCommandRequest) (<-chan ExecutionEvent, error)
	Protocol() string
}

type ExecCommandRequest struct {
	Command    string
	Args       []string
	Target     string
	Creds      *Credential
	Timeout    time.Duration
	WorkingDir string
	Env        map[string]string
}

type Planner interface {
	Evaluate(state any) []Action
}

type Action struct {
	ID            string
	Capabilities  []Capability
	Priority      int
	Confidence    float64
	NoiseScore    int
	Preconditions []Condition
	Description   string
}

type Condition struct {
	Type  string
	Value string
}

type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
	execs map[string]Executor
	caps  map[Capability][]string
}

func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
		execs: make(map[string]Executor),
		caps:  make(map[Capability][]string),
	}
}

func (r *Registry) RegisterTool(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
	for _, c := range t.Capabilities() {
		r.caps[c] = append(r.caps[c], t.Name())
	}
}

func (r *Registry) RegisterExecutor(name string, e Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.execs[name] = e
}

func (r *Registry) FindTool(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) FindWithCapability(c Capability) []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := r.caps[c]
	var tools []Tool
	for _, n := range names {
		if t, ok := r.tools[n]; ok {
			tools = append(tools, t)
		}
	}
	return tools
}

func (r *Registry) FindExecutor(protocol string) (Executor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.execs[protocol]
	return e, ok
}
