package core

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
	ID          int    `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	GUID        string `json:"guid" db:"guid"`
	Domain      string `json:"domain" db:"domain"`
	IsLinked    bool   `json:"is_linked" db:"is_linked"`
	CanEdit     bool   `json:"can_edit" db:"can_edit"`
}

type ADCSTemplate struct {
	ID          int    `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	Domain      string `json:"domain" db:"domain"`
	Vuln        string `json:"vuln" db:"vuln"` // ESC1, ESC8, etc.
	Enrollee    string `json:"enrollee" db:"enrollee"`
}

type User struct {
	ID             int      `json:"id" db:"id"`
	Username       string   `json:"username" db:"username"`
	Domain         string   `json:"domain" db:"domain"`
	SAMAccountName string   `json:"sam_account_name" db:"sam_account_name"`
	SID            string   `json:"sid" db:"sid"`
	Enabled        bool     `json:"enabled" db:"enabled"`
	IsAdmin        bool     `json:"is_admin" db:"is_admin"`
	IsDA           bool     `json:"is_da" db:"is_da"`
	Description    string   `json:"description" db:"description"`
	Source         string   `json:"source" db:"source"`
	SPNs           []string `json:"spns,omitempty" db:"-"`
	NoPreauth      bool     `json:"no_preauth" db:"no_preauth"`
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
	ID         int    `json:"id" db:"id"`
	HostID     int    `json:"host_id" db:"host_id"`
	UserID     int    `json:"user_id" db:"user_id"`
	Source     string `json:"source" db:"source"`
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
	ID        int      `json:"id" db:"id"`
	Type      CredType `json:"type" db:"type"`
	Username  string   `json:"username" db:"username"`
	Domain    string   `json:"domain" db:"domain"`
	Secret    string   `json:"secret,omitempty" db:"secret"`
	Hash      string   `json:"hash,omitempty" db:"hash"`
	Target    string   `json:"target" db:"target"`
	Validated bool     `json:"validated" db:"validated"`
	Source    string   `json:"source" db:"source"`
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
	PhaseSessionHarvest, PhaseGraphAnalysis, PhaseLateral,
	PhaseValidation, PhasePrivEsc, PhasePersistence,
}

func (p Phase) Dependencies() []Phase {
	switch p {
	case PhaseDiscovery:      return nil
	case PhaseEnumeration:    return []Phase{PhaseDiscovery}
	case PhaseCredentialAcq:  return []Phase{PhaseEnumeration}
	case PhaseSessionHarvest: return []Phase{PhaseEnumeration, PhaseCredentialAcq}
	case PhaseGraphAnalysis:  return []Phase{PhaseEnumeration}
	case PhaseLateral:        return []Phase{PhaseCredentialAcq, PhaseSessionHarvest}
	case PhaseValidation:     return []Phase{PhaseCredentialAcq}
	case PhasePrivEsc:        return []Phase{PhaseEnumeration, PhaseGraphAnalysis}
	case PhasePersistence:    return []Phase{PhaseCredentialAcq, PhasePrivEsc}
	}
	return nil
}

type PhaseStatus int
const (
	PhaseUntouched  PhaseStatus = 0
	PhaseInProgress PhaseStatus = 1
	PhaseComplete   PhaseStatus = 2
	PhaseSkipped    PhaseStatus = 3
)

type ADState struct {
	Hosts     []Host              `json:"hosts"`
	Users     []User              `json:"users"`
	Groups    []Group             `json:"groups"`
	Computers []Computer          `json:"computers"`
	Sessions  []Session           `json:"sessions"`
	Creds     []Credential        `json:"creds"`
	GPOs      []GPO               `json:"gpos"`
	ADCS      []ADCSTemplate      `json:"adcs"`
	BH        BloodhoundMeta      `json:"bloodhound"`
	Phases    map[Phase]PhaseStatus `json:"phases"`
}

type Gap struct {
	Phase    Phase  `json:"phase"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func (s *ADState) DetectGaps() []Gap {
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
			if c.Validated { validated++ }
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
	return g
}

func (s *ADState) NextPhase() *Phase {
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
		if s.Phases[PhaseLateral] != PhaseComplete {
			p := PhaseLateral
			return &p
		}
		if s.Phases[PhasePersistence] != PhaseComplete {
			p := PhasePersistence
			return &p
		}
	}

	depsMet := func(p Phase) bool {
		for _, dep := range p.Dependencies() {
			if s.Phases[dep] != PhaseComplete && s.Phases[dep] != PhaseSkipped {
				return false
			}
		}
		return true
	}
	for _, p := range AllPhases {
		st := s.Phases[p]
		if st == PhaseComplete || st == PhaseSkipped {
			continue
		}
		if depsMet(p) {
			return &p
		}
	}
	return nil
}

func NewADState() *ADState {
	return &ADState{Phases: make(map[Phase]PhaseStatus)}
}
