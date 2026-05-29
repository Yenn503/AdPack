package core

import (
	"sync"
	"time"
)

type TargetScope struct {
	CIDRs     []string `yaml:"cidrs" json:"cidrs"`
	Hostnames []string `yaml:"hostnames" json:"hostnames"`
	Domain    string   `yaml:"domain" json:"domain"`
	Username  string   `yaml:"username" json:"username"`
	Password  string   `yaml:"password" json:"password,omitempty"`
	Hash      string   `yaml:"hash" json:"hash,omitempty"`
	Krb5Cred  string   `yaml:"krb5_cred" json:"krb5_cred,omitempty"`
}

type Host struct {
	ID           int    `json:"id" db:"id"`
	IP           string `json:"ip" db:"ip"`
	Hostname     string `json:"hostname" db:"hostname"`
	Domain       string `json:"domain" db:"domain"`
	OS           string `json:"os" db:"os"`
	IsDC         bool   `json:"is_dc" db:"is_dc"`
	PortsOpen    string `json:"ports_open" db:"ports_open"`
	DiscoverySrc string `json:"discovery_src" db:"discovery_src"`
	EDR          string `json:"edr" db:"edr"`
	EvasionHist  string `json:"evasion_hist" db:"evasion_hist"` // JSON list of failed/successful profiles
}

type GPO struct {
	ID       int    `json:"id" db:"id"`
	Name     string `json:"name" db:"name"`
	GUID     string `json:"guid" db:"guid"`
	Domain   string `json:"domain" db:"domain"`
	IsLinked bool   `json:"is_linked" db:"is_linked"`
	CanEdit  bool   `json:"can_edit" db:"can_edit"`
}

// PrivilegeEdge represents a directed privilege relationship between two
// AD principals. The direction is SourcePrincipal → TargetPrincipal via
// AccessRight. For example:
//
//	SourcePrincipal: "SEVENKINGDOMS\WIN11_USER"
//	TargetPrincipal: "SEVENKINGDOMS\KINGSLANDING$"
//	AccessRight:     "HasSession"
//	EdgeType:        "mssql_impersonation"
//
//	SourcePrincipal: "SEVENKINGDOMS\stannis.baratheon"
//	TargetPrincipal: "SEVENKINGDOMS\KINGSLANDING$"
//	AccessRight:     "GenericAll"
//	EdgeType:        "acl"
type PrivilegeEdge struct {
	ID                 int                     `json:"id" db:"id"`
	SourcePrincipal    string                  `json:"source_principal" db:"source_principal"`
	TargetPrincipal    string                  `json:"target_principal" db:"target_principal"`
	AccessRight        string                  `json:"access_right" db:"access_right"`
	EdgeType           string                  `json:"edge_type" db:"edge_type"`
	Domain             string                  `json:"domain" db:"domain"`
	Source             string                  `json:"source" db:"source"` // "daclread", "bloodhound", "mssql_priv", "manual"
	Confidence         float64                 `json:"confidence" db:"confidence"`
	Weight             float64                 `json:"weight" db:"weight"`                 // lower = better path cost
	Exploitability     float64                 `json:"exploitability" db:"exploitability"` // 0.0-1.0, how easy to exploit
	Noise              float64                 `json:"noise" db:"noise"`                   // 0.0-1.0, how detectable
	Requires           []string                `json:"requires,omitempty" db:"-"`          // capabilities needed
	ValidationState    EdgeValidationState     `json:"validation_state" db:"validation_state"`
	ObservedAt         time.Time               `json:"observed_at" db:"observed_at"`
	ObservedBy         string                  `json:"observed_by" db:"observed_by"`   // module that recorded this edge
	Preconditions      []ExecutionPrecondition `json:"preconditions,omitempty" db:"-"` // runtime checks before edge is executable
	Provenance         string                  `json:"provenance" db:"provenance"`     // "bh", "relay", "resolver", "executor", "manual"
	LastVerifiedAt     time.Time               `json:"last_verified_at" db:"last_verified_at"`
	VerificationMethod string                  `json:"verification_method" db:"verification_method"`
}

// Stale returns true when the edge has not been re-verified within the
// staleness window, or when the validation state explicitly indicates
// staleness or degradation. A zero LastVerifiedAt means never verified.
func (e PrivilegeEdge) Stale(staleAfter time.Duration) bool {
	if e.ValidationState == EdgeStale || e.ValidationState == EdgeDegraded {
		return true
	}
	if e.LastVerifiedAt.IsZero() {
		return true
	}
	if staleAfter <= 0 {
		return false
	}
	return time.Since(e.LastVerifiedAt) > staleAfter
}

// MarkVerified updates the edge's confidence, verification timestamp, and
// method after a successful state-grounded check.
func (e *PrivilegeEdge) MarkVerified(confidence float64, method string) {
	e.Confidence = confidence
	e.LastVerifiedAt = time.Now()
	e.VerificationMethod = method
	e.ValidationState = EdgeValidated
}

// DegradeConfidence reduces the edge's confidence and marks it suspect
// without removing it. The planner will deprioritise suspect edges
// unless no higher-confidence path exists.
func (e *PrivilegeEdge) DegradeConfidence(newConf float64, reason string) {
	if newConf < 0 {
		newConf = 0
	}
	e.Confidence = newConf
	e.LastVerifiedAt = time.Now()
	e.VerificationMethod = "degraded:" + reason
	e.ValidationState = EdgeDegraded
}

// EdgeValidationState describes the confidence level of a privilege edge.
type EdgeValidationState string

const (
	EdgeInferred      EdgeValidationState = "inferred"      // derived from heuristics, not directly observed
	EdgeObserved      EdgeValidationState = "observed"      // directly observed by enumeration
	EdgeValidated     EdgeValidationState = "validated"     // confirmed exploitable via execution
	EdgeStale         EdgeValidationState = "stale"         // may no longer be valid
	EdgeDegraded      EdgeValidationState = "degraded"      // re-verification failed, confidence lowered
	EdgeProbabilistic EdgeValidationState = "probabilistic" // exists with some probability < 1.0
)

// ExecutionPrecondition describes a runtime check that must pass before a
// privilege edge can be operationalised. Preconditions bridge the gap between
// "graph says this relationship exists" and "we can actually execute this now."
//
// Kind identifies what to check (e.g. "port_open", "service_running",
// "protocol_reachable", "auth_works", "privilege_held"). Description is
// human-readable context for explainability.
type ExecutionPrecondition struct {
	Kind        string `json:"kind" db:"kind"`
	Target      string `json:"target" db:"target"` // host/principal this applies to
	Port        int    `json:"port,omitempty" db:"port"`
	Description string `json:"description,omitempty" db:"-"`
}

// Precondition kinds used across edge types.
const (
	PrecondPortOpen          = "port_open"
	PrecondProtocolReachable = "protocol_reachable"
	PrecondAuthWorks         = "auth_works"
	PrecondServiceRunning    = "service_running"
	PrecondPrivilegeHeld     = "privilege_held"
)

// ExecutionState tracks what the planner knows about runtime feasibility.
// This is populated by execution feedback and discovery probes, and consumed
// by the planner to prune infeasible edges.
type ExecutionState struct {
	ReachableHosts map[string]bool    `json:"reachable_hosts"`
	OpenPorts      map[string][]int   `json:"open_ports"`   // host IP → ports
	ValidCreds     map[string]bool    `json:"valid_creds"`  // "DOMAIN\user" → validated
	BurnedHosts    map[string]float64 `json:"burned_hosts"` // host IP → burn score (0-1)
}

type ADCSTemplate struct {
	ID                      int      `json:"id" db:"id"`
	Name                    string   `json:"name" db:"name"`
	DisplayName             string   `json:"display_name" db:"display_name"`
	Domain                  string   `json:"domain" db:"domain"`
	CA                      string   `json:"ca" db:"ca"`
	Enabled                 bool     `json:"enabled" db:"enabled"`
	ClientAuth              bool     `json:"client_auth" db:"client_auth"`
	EnrolleeSuppliesSubject bool     `json:"enrollee_supplies_subject" db:"enrollee_supplies_subject"`
	RequiresManagerApproval bool     `json:"requires_manager_approval" db:"requires_manager_approval"`
	AuthorizedSignatures    int      `json:"authorized_signatures" db:"authorized_signatures"`
	SchemaVersion           int      `json:"schema_version" db:"schema_version"`
	EKUs                    []string `json:"ekus" db:"-"`
	Vuln                    string   `json:"vuln" db:"vuln"` // ESC1, ESC8, etc.
	Enrollee                string   `json:"enrollee" db:"enrollee"`
}

type User struct {
	ID             int    `json:"id" db:"id"`
	Username       string `json:"username" db:"username"`
	Domain         string `json:"domain" db:"domain"`
	SAMAccountName string `json:"sam_account_name" db:"sam_account_name"`
	SID            string `json:"sid" db:"sid"`
	Enabled        bool   `json:"enabled" db:"enabled"`
	IsAdmin        bool   `json:"is_admin" db:"is_admin"`
	IsDA           bool   `json:"is_da" db:"is_da"`
	Description    string `json:"description" db:"description"`
	Source         string `json:"source" db:"source"`
	SPNs           string `json:"spns,omitempty" db:"spns"`
	NoPreauth      bool   `json:"no_preauth" db:"no_preauth"`
}

type Group struct {
	ID          int    `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	Domain      string `json:"domain" db:"domain"`
	SID         string `json:"sid" db:"sid"`
	Description string `json:"description" db:"description"`
	MemberCount int    `json:"member_count" db:"member_count"`
}

type Computer struct {
	ID              int    `json:"id" db:"id"`
	Name            string `json:"name" db:"name"`
	Domain          string `json:"domain" db:"domain"`
	SID             string `json:"sid" db:"sid"`
	OperatingSystem string `json:"operating_system" db:"operating_system"`
	IsDC            bool   `json:"is_dc" db:"is_dc"`
}

type Session struct {
	ID     int    `json:"id" db:"id"`
	HostID int    `json:"host_id" db:"host_id"`
	UserID int    `json:"user_id" db:"user_id"`
	Source string `json:"source" db:"source"`

	// Transient parser fields (not persisted to DB, populated by parseSMBSessions).
	Username string `json:"username,omitempty"`
	Host     string `json:"host,omitempty"`      // target IP where session was found
	SourceIP string `json:"source_ip,omitempty"` // "(from x.x.x.x)" origin
}

type CredType string

const (
	CredPlaintext CredType = "plaintext"
	CredHash      CredType = "hash"
	CredTicket    CredType = "ticket"
	CredToken     CredType = "token"
	CredCert      CredType = "certificate"
)

type Credential struct {
	ID            int      `json:"id" db:"id"`
	Type          CredType `json:"type" db:"type"`
	Username      string   `json:"username" db:"username"`
	Domain        string   `json:"domain" db:"domain"`
	Secret        string   `json:"secret,omitempty" db:"secret"`
	Hash          string   `json:"hash,omitempty" db:"hash"`
	Target        string   `json:"target" db:"target"`
	Validated     bool     `json:"validated" db:"validated"`
	Source        string   `json:"source" db:"source"`
	SourceTool    string   `json:"source_tool" db:"source_tool"`
	TargetAccount string   `json:"target_account" db:"target_account"`
	Confidence    float64  `json:"confidence" db:"confidence"`
}

type BloodhoundMeta struct {
	ID            int    `json:"id" db:"id"`
	Collected     bool   `json:"collected" db:"collected"`
	Ingested      bool   `json:"ingested" db:"ingested"`
	FilePath      string `json:"file_path" db:"file_path"`
	DAUsers       string `json:"da_users" db:"da_users"`
	DACount       int    `json:"da_count" db:"da_count"`
	OutboundTrust bool   `json:"outbound_trust" db:"outbound_trust"`
}

type Phase string

const (
	PhaseDiscovery      Phase = "discovery"
	PhaseEnumeration    Phase = "enumeration"
	PhaseCredentialAcq  Phase = "credential_acq"
	PhaseSessionHarvest Phase = "session_harvest"
	PhaseGraphAnalysis  Phase = "graph_analysis"
	PhaseLateral        Phase = "lateral"
	PhaseValidation     Phase = "validation"
	PhasePrivEsc        Phase = "privesc"
	PhasePersistence    Phase = "persistence"
)

var AllPhases = []Phase{
	PhaseDiscovery, PhaseEnumeration, PhaseCredentialAcq,
	PhaseSessionHarvest, PhaseGraphAnalysis, PhaseValidation,
	PhasePrivEsc, PhaseLateral, PhasePersistence,
}

func (p Phase) Dependencies() []Phase {
	switch p {
	case PhaseDiscovery:
		return nil
	case PhaseEnumeration:
		return []Phase{PhaseDiscovery}
	case PhaseCredentialAcq:
		return []Phase{PhaseEnumeration}
	case PhaseSessionHarvest:
		return []Phase{PhaseEnumeration, PhaseCredentialAcq}
	case PhaseGraphAnalysis:
		return []Phase{PhaseEnumeration}
	case PhaseLateral:
		return []Phase{PhaseCredentialAcq, PhaseSessionHarvest}
	case PhaseValidation:
		return []Phase{PhaseCredentialAcq}
	case PhasePrivEsc:
		return []Phase{PhaseEnumeration, PhaseGraphAnalysis}
	case PhasePersistence:
		return []Phase{PhaseCredentialAcq, PhasePrivEsc}
	}
	return nil
}

type PhaseStatus int

const (
	PhaseUntouched  PhaseStatus = 0
	PhaseInProgress PhaseStatus = 1
	PhaseComplete   PhaseStatus = 2
	PhaseSkipped    PhaseStatus = 3
	PhaseFailed     PhaseStatus = 4
)

type SkipReason string

const (
	SkipNoCreds         SkipReason = "NO_CREDS"
	SkipNoSession       SkipReason = "NO_SESSION"
	SkipNoPath          SkipReason = "NO_PATH"
	SkipNoDCSyncRights  SkipReason = "NO_DCSYNC_RIGHTS"
	SkipNoSystemContext SkipReason = "NO_SYSTEM_CONTEXT"
)

type ADState struct {
	mu              sync.RWMutex              `json:"-"`
	Hosts           []Host                    `json:"hosts"`
	Users           []User                    `json:"users"`
	Groups          []Group                   `json:"groups"`
	Computers       []Computer                `json:"computers"`
	Sessions        []Session                 `json:"sessions"`
	Creds           []Credential              `json:"creds"`
	GPOs            []GPO                     `json:"gpos"`
	ADCS            []ADCSTemplate            `json:"adcs"`
	Edges           []PrivilegeEdge           `json:"edges"`
	EdgeEvents      map[EdgeKey][]EdgeEvent   `json:"edge_events,omitempty"`
	BH              BloodhoundMeta            `json:"bloodhound"`
	Exec            ExecutionState            `json:"exec"`
	Runtime         RuntimeState              `json:"runtime"`
	Mutation        StateMutation             `json:"mutation"`
	Phases          map[Phase]PhaseStatus     `json:"phases"`
	SkipReasons     map[Phase]SkipReason      `json:"skip_reasons,omitempty"`
	Scope           []string                  `json:"scope,omitempty"`
	PhaseExecutions map[Phase]*PhaseExecution `json:"phase_executions,omitempty"`
}

type Gap struct {
	Phase    Phase  `json:"phase"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func (s *ADState) DetectGaps() []Gap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var g []Gap
	if len(s.Hosts) == 0 {
		g = append(g, Gap{PhaseDiscovery, "high", "No hosts discovered"})
	}
	if len(s.Hosts) > 0 && len(s.Users) == 0 {
		g = append(g, Gap{PhaseEnumeration, "high", "No users enumerated"})
	}
	if len(s.Hosts) > 0 && len(s.Computers) == 0 {
		g = append(g, Gap{PhaseEnumeration, "medium", "No computers enumerated"})
	}
	if len(s.Users) > 0 && len(s.Creds) == 0 {
		g = append(g, Gap{PhaseCredentialAcq, "high", "No credentials acquired"})
	}
	if len(s.Creds) > 0 {
		validated := 0
		for _, c := range s.Creds {
			if c.Validated {
				validated++
			}
		}
		if validated == 0 {
			g = append(g, Gap{PhaseValidation, "high", "No credentials validated"})
		}
		allValidated := validated == len(s.Creds)
		if allValidated && len(s.Sessions) == 0 {
			g = append(g, Gap{PhaseSessionHarvest, "medium", "No sessions discovered"})
		}
	}
	if !s.BH.Collected {
		g = append(g, Gap{PhaseGraphAnalysis, "medium", "BloodHound data not collected"})
	}
	if len(s.Users) > 0 && len(s.Edges) == 0 {
		g = append(g, Gap{PhasePrivEsc, "high", "No ACL privilege edges enumerated. Run daclread to discover escalation paths."})
	}
	return g
}

func (s *ADState) NextPhase() *Phase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Fast-track logic: if we have DA creds validated, jump to persistence or lateral movement
	hasDA := false
	for _, c := range s.Creds {
		if c.Validated {
			for _, u := range s.Users {
				if u.Username == c.Username && u.IsDA {
					hasDA = true
					break
				}
			}
		}
	}

	if hasDA {
		if s.Phases[PhaseLateral] != PhaseComplete && s.Phases[PhaseLateral] != PhaseFailed && s.Phases[PhaseLateral] != PhaseSkipped {
			p := PhaseLateral
			return &p
		}
		if s.Phases[PhasePersistence] != PhaseComplete && s.Phases[PhasePersistence] != PhaseFailed && s.Phases[PhasePersistence] != PhaseSkipped {
			p := PhasePersistence
			return &p
		}
	}

	depsMet := func(p Phase) bool {
		for _, dep := range p.Dependencies() {
			if s.Phases[dep] != PhaseComplete && s.Phases[dep] != PhaseSkipped && s.Phases[dep] != PhaseFailed {
				return false
			}
		}
		return true
	}
	for _, p := range AllPhases {
		st := s.Phases[p]
		if st == PhaseComplete || st == PhaseSkipped || st == PhaseFailed {
			continue
		}
		if depsMet(p) {
			return &p
		}
	}
	return nil
}

func NewADState() *ADState {
	return &ADState{
		Phases:          make(map[Phase]PhaseStatus),
		SkipReasons:     make(map[Phase]SkipReason),
		EdgeEvents:      make(map[EdgeKey][]EdgeEvent),
		PhaseExecutions: make(map[Phase]*PhaseExecution),
	}
}

// EmitEdgeEvent applies an event through the reducer, updates the matching
// edge in-place, and appends the event to the event log. Returns the
// volatility score from the reducer.
func (s *ADState) EmitEdgeEvent(edgeKey EdgeKey, ev EdgeEvent) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.Edges {
		if EdgeKeyOf(e) != edgeKey {
			continue
		}
		updated, vol := ReduceEdgeEvent(e, ev)
		s.Edges[i] = updated
		s.EdgeEvents[edgeKey] = append(s.EdgeEvents[edgeKey], ev)
		return vol
	}
	// Edge not found — log event anyway for audit
	s.EdgeEvents[edgeKey] = append(s.EdgeEvents[edgeKey], ev)
	return 0
}
