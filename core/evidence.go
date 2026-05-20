package core

import "time"

type EvidenceType string

const (
	EvHostFound      EvidenceType = "host_found"
	EvUserEnumerated EvidenceType = "user_enumerated"
	EvCredAcquired   EvidenceType = "credential_acquired"
	EvSessionFound   EvidenceType = "session_found"
	EvCredValidated  EvidenceType = "credential_validated"
)

type EvidenceEntry struct {
	ID         int          `json:"id" db:"id"`
	ParentID   int          `json:"parent_id" db:"parent_id"` // Link to previous evidence
	Type       EvidenceType `json:"type" db:"type"`
	Phase      Phase        `json:"phase" db:"phase"`
	Source     string       `json:"source" db:"source"`
	Key        string       `json:"key" db:"key"`
	Value      string       `json:"value" db:"value"`
	Confidence float64      `json:"confidence" db:"confidence"`
	RawOutput  string       `json:"raw_output,omitempty" db:"raw_output"`
	Timestamp  time.Time    `json:"timestamp" db:"timestamp"`
}

type ToolResult struct {
	Success   bool
	Evidence  []EvidenceEntry
	Hosts     []Host
	Users     []User
	Groups    []Group
	Computers []Computer
	GPOs      []GPO
	ADCS      []ADCSTemplate
	Sessions  []Session
	Creds     []Credential
	RawOutput string
}
