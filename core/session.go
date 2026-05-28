package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SessionSummary is a lightweight envelope for fast listing without full deserialization.
type SessionSummary struct {
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	Hosts     int       `json:"hosts"`
	Creds     int       `json:"creds"`
	Edges     int       `json:"edges"`
	Phase     string    `json:"phase"`
	Timestamp time.Time `json:"timestamp"`
}

// SessionData is the full serializable session envelope.
type SessionData struct {
	Summary SessionSummary `json:"summary"`
	State   *ADState       `json:"state"`
}

// SessionDir returns the sessions directory path.
func SessionDir() string {
	return filepath.Join(os.Getenv("HOME"), ".adpack", "sessions")
}

// ValidateSessionName checks for path traversal and empty names.
func ValidateSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("session name cannot be empty")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("session name contains invalid characters: %s", name)
	}
	return nil
}

// SaveSession serializes ADState to sessions/<name>.json.
func SaveSession(name string, state *ADState) error {
	if err := ValidateSessionName(name); err != nil {
		return err
	}
	dir := SessionDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create sessions dir: %w", err)
	}

	currentPhase := "none"
	for _, p := range AllPhases {
		if state.Phases[p] == PhaseInProgress {
			currentPhase = string(p)
			break
		}
	}
	if currentPhase == "none" {
		for i := len(AllPhases) - 1; i >= 0; i-- {
			if state.Phases[AllPhases[i]] == PhaseComplete {
				currentPhase = string(AllPhases[i])
				break
			}
		}
	}

	domain := ""
	if len(state.Hosts) > 0 {
		domain = state.Hosts[0].Domain
	}

	data := SessionData{
		Summary: SessionSummary{
			Name:      name,
			Domain:    domain,
			Hosts:     len(state.Hosts),
			Creds:     len(state.Creds),
			Edges:     len(state.Edges),
			Phase:     currentPhase,
			Timestamp: time.Now(),
		},
		State: state,
	}

	path := filepath.Join(dir, name+".json")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create session file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	return nil
}

// LoadSession deserializes a session from sessions/<name>.json.
func LoadSession(name string) (*ADState, error) {
	if err := ValidateSessionName(name); err != nil {
		return nil, err
	}
	path := filepath.Join(SessionDir(), name+".json")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open session file: %w", err)
	}
	defer f.Close()

	var data SessionData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}
	return data.State, nil
}

// ListSessions returns all saved session summaries without full deserialization.
func ListSessions() ([]SessionSummary, error) {
	dir := SessionDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sessions dir: %w", err)
	}

	var summaries []SessionSummary
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var data SessionData
		if err := json.NewDecoder(f).Decode(&data); err != nil {
			f.Close()
			continue
		}
		f.Close()
		data.Summary.Name = strings.TrimSuffix(e.Name(), ".json")
		summaries = append(summaries, data.Summary)
	}
	return summaries, nil
}

// DeleteSession removes a session file.
func DeleteSession(name string) error {
	if err := ValidateSessionName(name); err != nil {
		return err
	}
	path := filepath.Join(SessionDir(), name+".json")
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// ExportSession writes a session to an arbitrary file path (portable JSON envelope).
func ExportSession(name string, outputPath string) error {
	if err := ValidateSessionName(name); err != nil {
		return err
	}
	src := filepath.Join(SessionDir(), name+".json")
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read session: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	return nil
}

// ImportSession reads a portable JSON envelope and saves it as a named session.
func ImportSession(name string, inputPath string) error {
	if err := ValidateSessionName(name); err != nil {
		return err
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read import file: %w", err)
	}
	var sd SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("parse session envelope: %w", err)
	}
	if sd.State == nil {
		return fmt.Errorf("import file missing state field")
	}
	dir := SessionDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create sessions dir: %w", err)
	}
	sd.Summary.Name = name
	sd.Summary.Timestamp = time.Now()
	dest := filepath.Join(dir, name+".json")
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create session file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(sd)
}

// ValidateSessionHealth checks a loaded session for consistency and reports issues.
func ValidateSessionHealth(state *ADState) []string {
	var issues []string
	if len(state.Hosts) == 0 {
		issues = append(issues, "no hosts in state")
	}
	if len(state.Creds) == 0 {
		issues = append(issues, "no credentials in state")
	}
	if state.Phases == nil {
		issues = append(issues, "phase map is nil")
	}
	// Check for creds referencing unknown hosts
	hostSet := make(map[string]bool)
	for _, h := range state.Hosts {
		hostSet[h.IP] = true
		hostSet[h.Hostname] = true
	}
	for _, c := range state.Creds {
		if c.Target != "" && !hostSet[c.Target] {
			issues = append(issues, fmt.Sprintf("credential for %s references unknown target %s", c.Username, c.Target))
		}
	}
	// Check for edges with missing endpoints
	for i, e := range state.Edges {
		if e.SourcePrincipal != "" && !hostSet[e.SourcePrincipal] {
			issues = append(issues, fmt.Sprintf("edge[%d] source %s not in hosts", i, e.SourcePrincipal))
		}
		if e.TargetPrincipal != "" && !hostSet[e.TargetPrincipal] {
			issues = append(issues, fmt.Sprintf("edge[%d] target %s not in hosts", i, e.TargetPrincipal))
		}
	}
	return issues
}
