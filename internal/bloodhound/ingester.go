package bloodhound

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"adpack/core"
	"adpack/utils"
)

// CollectConfig controls how bloodhound-python is invoked.
type CollectConfig struct {
	Domain    string
	Username  string
	Password  string
	Hash      string
	DCHost    string
	DNSHost   string
	OutputDir string
	// Collection methods: Group, LocalAdmin, Session, Trusts, ACL, DCOM, RDP, PSRemote, LoggedOn, ObjectProps, Container
	Methods []string
}

// DefaultMethods is the standard set for graph enrichment.
var DefaultMethods = []string{"Group", "LocalAdmin", "Session", "Trusts", "ACL", "ObjectProps", "Container"}

// CollectAndIngest runs bloodhound-python, parses output, and converts to state.
func CollectAndIngest(ctx context.Context, cfg CollectConfig, state *core.ADState) error {
	dir, err := runBloodhound(ctx, cfg)
	if err != nil {
		return fmt.Errorf("bloodhound collection: %w", err)
	}

	p, err := ParseDirectory(dir)
	if err != nil {
		return fmt.Errorf("bloodhound parse: %w", err)
	}

	bhState := p.ConvertToState(strings.ToLower(cfg.Domain))

	// Merge BH state into the existing state
	mergeState(state, bhState)

	state.BH.Collected = true
	state.BH.Ingested = true

	return nil
}

// IngestFromDirectory parses BloodHound JSON files from a directory and
// merges the results into the given state. This is useful if you've already
// collected BH data separately.
func IngestFromDirectory(dir, domain string, state *core.ADState) error {
	p, err := ParseDirectory(dir)
	if err != nil {
		return fmt.Errorf("bloodhound parse: %w", err)
	}

	bhState := p.ConvertToState(strings.ToLower(domain))
	mergeState(state, bhState)
	state.BH.Ingested = true
	return nil
}

// IngestFromFiles parses BloodHound JSON data from raw byte slices and
// merges the results into the given state.
func IngestFromFiles(usersJSON, groupsJSON, computersJSON, domainsJSON []byte, domain string, state *core.ADState) error {
	p, err := ParseBytes(usersJSON, groupsJSON, computersJSON, domainsJSON)
	if err != nil {
		return fmt.Errorf("bloodhound parse: %w", err)
	}

	bhState := p.ConvertToState(strings.ToLower(domain))
	mergeState(state, bhState)
	state.BH.Ingested = true
	return nil
}

// runBloodhound executes bloodhound-python and returns the output directory.
func runBloodhound(ctx context.Context, cfg CollectConfig) (string, error) {
	var err error
	createdTempDir := false
	if cfg.OutputDir == "" {
		cfg.OutputDir, err = os.MkdirTemp("", "bloodhound-*")
		if err != nil {
			return "", fmt.Errorf("create temp dir: %w", err)
		}
		createdTempDir = true
	}
	cleanupTemp := func() {
		if createdTempDir {
			os.RemoveAll(cfg.OutputDir)
		}
	}

	method := strings.Join(cfg.Methods, ",")
	if method == "" {
		method = strings.Join(DefaultMethods, ",")
	}

	args := []string{
		"-d", cfg.Domain,
		"-u", cfg.Username,
		"--zip",
	}

	if cfg.Password != "" {
		args = append(args, "-p", cfg.Password)
	}
	if cfg.Hash != "" {
		// bloodhound-python expects LM:NT format, prefix null LM hash
		args = append(args, "--hashes", "aad3b435b51404eeaad3b435b51404ee:"+cfg.Hash)
	}
	if cfg.DCHost != "" {
		args = append(args, "-dc", cfg.DCHost)
	}
	if cfg.DNSHost != "" {
		args = append(args, "-ns", cfg.DNSHost)
	}

	args = append(args, "-c", method, "--disable-autogc")

	cmd := exec.CommandContext(ctx, "bloodhound-python", args...)
	cmd.Dir = cfg.OutputDir

	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanupTemp()
		return cfg.OutputDir, fmt.Errorf("bloodhound-python failed: %w\n%s", err, string(out))
	}

	// Find and extract the zip file
	entries, err := os.ReadDir(cfg.OutputDir)
	if err != nil {
		cleanupTemp()
		return cfg.OutputDir, fmt.Errorf("read output dir: %w", err)
	}

	var zipPath string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".zip") && strings.Contains(e.Name(), "bloodhound") {
			zipPath = filepath.Join(cfg.OutputDir, e.Name())
			break
		}
	}
	if zipPath == "" {
		// Maybe bloodhound-python didn't use --zip; files are already extracted
		return cfg.OutputDir, nil
	}

	// Extract the zip
	if err := utils.Unzip(zipPath, cfg.OutputDir); err != nil {
		cleanupTemp()
		return cfg.OutputDir, fmt.Errorf("extract bloodhound zip: %w", err)
	}

	// Remove zip to keep directory clean
	os.Remove(zipPath)

	if createdTempDir {
		defer os.RemoveAll(cfg.OutputDir)
	}

	return cfg.OutputDir, nil
}

// mergeState merges BloodHound-derived data into the target state.
// Users, groups, and computers are appended; edges are deduplicated by
// source|target|right key.
func mergeState(target, src *core.ADState) {
	// Merge users
	seenUsers := make(map[string]bool)
	for _, u := range target.Users {
		seenUsers[u.Username] = true
	}
	for _, u := range src.Users {
		if !seenUsers[u.Username] {
			seenUsers[u.Username] = true
			target.Users = append(target.Users, u)
		}
	}

	// Merge groups
	seenGroups := make(map[string]bool)
	for _, g := range target.Groups {
		seenGroups[g.Name] = true
	}
	for _, g := range src.Groups {
		if !seenGroups[g.Name] {
			seenGroups[g.Name] = true
			target.Groups = append(target.Groups, g)
		}
	}

	// Merge computers
	seenComputers := make(map[string]bool)
	for _, c := range target.Computers {
		seenComputers[c.Name] = true
	}
	for _, c := range src.Computers {
		if !seenComputers[c.Name] {
			seenComputers[c.Name] = true
			target.Computers = append(target.Computers, c)
		}
	}

	// Merge edges (deduplicate by source|target|right)
	seenEdges := make(map[string]bool)
	for _, e := range target.Edges {
		key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
		seenEdges[key] = true
	}
	for _, e := range src.Edges {
		key := e.SourcePrincipal + "|" + e.TargetPrincipal + "|" + e.AccessRight
		if !seenEdges[key] {
			seenEdges[key] = true
			target.Edges = append(target.Edges, e)
		}
	}
}
