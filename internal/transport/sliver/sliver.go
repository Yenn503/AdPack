package sliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"adpack/core"
)

// Transport executes commands on targets through Sliver C2 implants.
// Uses the sliver-client CLI for command execution.
type Transport struct {
	configPath string
	serverAddr string
}

// New creates a Sliver transport. configPath is the sliver client config.
// If empty, defaults to ~/.sliver-client/configs/default.cfg.
func New(configPath, serverAddr string) *Transport {
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = home + "/.sliver-client/configs/default.cfg"
	}
	return &Transport{configPath: configPath, serverAddr: serverAddr}
}

func (t *Transport) Execute(ctx context.Context, target core.HostRef, command string) (string, error) {
	sessionID, err := t.findSession(target)
	if err != nil {
		return "", fmt.Errorf("sliver: find session for %s: %w", target.Name, err)
	}

	args := []string{"-c", t.configPath}
	if t.serverAddr != "" {
		args = append(args, "-s", t.serverAddr)
	}
	args = append(args, "execute", "-i", sessionID, "-o", command)

	cmd := exec.CommandContext(ctx, "sliver-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sliver execute: %w (output: %s)", err, string(out))
	}
	return string(out), nil
}

func (t *Transport) Upload(ctx context.Context, target core.HostRef, localPath, remotePath string) error {
	sessionID, err := t.findSession(target)
	if err != nil {
		return fmt.Errorf("sliver: find session for %s: %w", target.Name, err)
	}

	args := []string{"-c", t.configPath}
	if t.serverAddr != "" {
		args = append(args, "-s", t.serverAddr)
	}
	args = append(args, "upload", "-i", sessionID, localPath, remotePath)

	cmd := exec.CommandContext(ctx, "sliver-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sliver upload: %w (output: %s)", err, string(out))
	}
	return nil
}

func (t *Transport) Download(ctx context.Context, target core.HostRef, remotePath, localPath string) error {
	sessionID, err := t.findSession(target)
	if err != nil {
		return fmt.Errorf("sliver: find session for %s: %w", target.Name, err)
	}

	args := []string{"-c", t.configPath}
	if t.serverAddr != "" {
		args = append(args, "-s", t.serverAddr)
	}
	args = append(args, "download", "-i", sessionID, remotePath, "-o", localPath)

	cmd := exec.CommandContext(ctx, "sliver-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sliver download: %w (output: %s)", err, string(out))
	}
	return nil
}

func (t *Transport) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	args := []string{"-c", t.configPath}
	if t.serverAddr != "" {
		args = append(args, "-s", t.serverAddr)
	}
	args = append(args, "sessions", "-f", "json")

	cmd := exec.CommandContext(ctx, "sliver-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sliver list sessions: %w", err)
	}
	return parseSessionsJSON(string(out))
}

func (t *Transport) findSession(target core.HostRef) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sessions, err := t.ListSessions(ctx)
	if err != nil {
		return "", err
	}

	// Match by hostname (case-insensitive)
	targetUpper := strings.ToUpper(target.Name)
	for _, s := range sessions {
		if strings.ToUpper(s.Hostname) == targetUpper || strings.ToUpper(s.IP) == targetUpper {
			return s.ID, nil
		}
	}

	// If no exact match, return first active session
	for _, s := range sessions {
		if s.Status == "active" {
			return s.ID, nil
		}
	}

	return "", fmt.Errorf("no active sliver session found for %s", target.Name)
}

// SessionInfo represents a Sliver implant session.
type SessionInfo struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Status   string `json:"status"`
}

func parseSessionsJSON(output string) ([]SessionInfo, error) {
	var sessions []SessionInfo

	start := strings.Index(output, "[")
	end := strings.LastIndex(output, "]")
	if start < 0 || end < 0 {
		return nil, fmt.Errorf("no JSON array found in sliver output")
	}

	jsonStr := output[start : end+1]
	if err := json.Unmarshal([]byte(jsonStr), &sessions); err != nil {
		return nil, fmt.Errorf("parse sliver sessions JSON: %w", err)
	}

	return sessions, nil
}
