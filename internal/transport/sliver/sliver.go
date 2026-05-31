package sliver

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"adpack/core"
)

type Transport struct {
	configPath string
	serverAddr string
	rcDir      string
	cache      sessionCache
}

type SessionStatus struct {
	ID          string
	Hostname    string
	IP          string
	Transport   string
	LastCheckIn time.Time
}

type sessionCache struct {
	mu       sync.Mutex
	sessions []sessionInfo
	expires  time.Time
	ttl      time.Duration
}

func (t *Transport) GetCachedSessions() []sessionInfo {
	t.cache.mu.Lock()
	defer t.cache.mu.Unlock()
	if time.Now().Before(t.cache.expires) {
		return t.cache.sessions
	}
	return nil
}

func New(configPath, serverAddr string) *Transport {
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".sliver-client", "configs", "default.cfg")
	}
	rcDir := filepath.Join(os.TempDir(), "adpack-sliver")
	os.MkdirAll(rcDir, 0700)
	return &Transport{
		configPath: configPath,
		serverAddr: serverAddr,
		rcDir:      rcDir,
		cache: sessionCache{
			ttl: 30 * time.Second,
		},
	}
}

func (t *Transport) Type() string {
	return "sliver"
}

func (t *Transport) Exec(ctx context.Context, target core.HostRef, command string, timeout time.Duration) core.ExecResult {
	sessionID, err := t.findSession(ctx, target)
	if err != nil {
		return core.ExecResult{Error: fmt.Sprintf("sliver: find session: %v", err)}
	}

	rc := fmt.Sprintf("use %s\nexecute --output -- %s\nexit\n", sessionID, command)
	out, err := t.runRC(ctx, rc, timeout)
	if err != nil {
		return core.ExecResult{
			Stdout: out,
			Error:  fmt.Sprintf("sliver exec: %v", err),
		}
	}

	// Strip the "use" banner from output — text before the first newline after "[*] Active session"
	clean := stripSliverBanner(out)
	return core.ExecResult{Stdout: clean, ExitCode: 0}
}

func (t *Transport) Upload(ctx context.Context, target core.HostRef, data []byte, remoteDir, remoteName string) (string, error) {
	sessionID, err := t.findSession(ctx, target)
	if err != nil {
		return "", fmt.Errorf("sliver: find session: %w", err)
	}

	tmpFile := filepath.Join(t.rcDir, fmt.Sprintf("upload_%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return "", fmt.Errorf("sliver: write temp upload: %w", err)
	}
	defer os.Remove(tmpFile)

	remotePath := filepath.Join(remoteDir, remoteName)
	rc := fmt.Sprintf("use %s\nupload %s %s\nexit\n", sessionID, tmpFile, remotePath)
	if _, err := t.runRC(ctx, rc, 60*time.Second); err != nil {
		return "", fmt.Errorf("sliver upload: %w", err)
	}
	return remotePath, nil
}

func (t *Transport) Download(ctx context.Context, target core.HostRef, remotePath string) ([]byte, error) {
	sessionID, err := t.findSession(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("sliver: find session: %w", err)
	}

	localPath := filepath.Join(t.rcDir, fmt.Sprintf("download_%d", time.Now().UnixNano()))

	rc := fmt.Sprintf("use %s\ndownload %s %s\nexit\n", sessionID, remotePath, localPath)
	if _, err := t.runRC(ctx, rc, 120*time.Second); err != nil {
		return nil, fmt.Errorf("sliver download: %v", err)
	}
	defer os.Remove(localPath)

	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("sliver: read downloaded file: %w", err)
	}
	return data, nil
}

func (t *Transport) buildArgs(rcFile string) []string {
	args := []string{"--rc", rcFile}
	if t.configPath != "" {
		args = append(args, "-c", t.configPath)
	}
	if t.serverAddr != "" {
		args = append(args, "-s", t.serverAddr)
	}
	return args
}

func (t *Transport) runRC(ctx context.Context, rcContent string, timeout time.Duration) (string, error) {
	rcFile := filepath.Join(t.rcDir, fmt.Sprintf("rc_%d", time.Now().UnixNano()))
	if err := os.WriteFile(rcFile, []byte(rcContent), 0600); err != nil {
		return "", fmt.Errorf("write rc file: %w", err)
	}
	defer os.Remove(rcFile)

	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := t.buildArgs(rcFile)
	cmd := exec.CommandContext(ctx, "sliver-client", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w (output: %s)", err, string(out))
	}
	return string(out), nil
}

type sessionInfo struct {
	ID       string
	Hostname string
	IP       string
}

func (t *Transport) findSession(ctx context.Context, target core.HostRef) (string, error) {
	t.cache.mu.Lock()
	cached := time.Now().Before(t.cache.expires) && len(t.cache.sessions) > 0
	var sessions []sessionInfo
	if cached {
		sessions = t.cache.sessions
		t.cache.mu.Unlock()
	} else {
		t.cache.mu.Unlock()
		rc := "sessions\nexit\n"
		out, err := t.runRC(ctx, rc, 30*time.Second)
		if err != nil {
			return "", fmt.Errorf("list sessions: %v", err)
		}

		sessions = parseSessions(out)
		t.cache.mu.Lock()
		t.cache.sessions = sessions
		t.cache.expires = time.Now().Add(t.cache.ttl)
		t.cache.mu.Unlock()
	}

	if len(sessions) == 0 {
		return "", fmt.Errorf("no sliver sessions")
	}

	if target.Name == "" {
		return sessions[0].ID, nil
	}

	targetUpper := strings.ToUpper(target.Name)
	for _, s := range sessions {
		if strings.ToUpper(s.Hostname) == targetUpper || strings.ToUpper(s.IP) == targetUpper {
			return s.ID, nil
		}
	}

	return sessions[0].ID, nil
}

func (t *Transport) SessionStatusList() []SessionStatus {
	t.cache.mu.Lock()
	sessions := t.cache.sessions
	t.cache.mu.Unlock()

	if len(sessions) == 0 {
		return nil
	}

	statuses := make([]SessionStatus, 0, len(sessions))
	for _, s := range sessions {
		statuses = append(statuses, SessionStatus{
			ID:        s.ID,
			Hostname:  s.Hostname,
			IP:        s.IP,
			Transport: "sliver",
		})
	}
	return statuses
}

func parseSessions(output string) []sessionInfo {
	lines := strings.Split(output, "\n")
	var sessions []sessionInfo
	inTable := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "ID") && strings.Contains(trimmed, "Transport") && strings.Contains(trimmed, "Hostname") {
			inTable = true
			continue
		}
		if strings.HasPrefix(trimmed, "==") {
			continue
		}
		if !inTable || trimmed == "" {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) >= 5 {
			remoteAddr := fields[3]
			hostname := fields[4]
			ip := remoteAddr
			if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
				ip = host
			}
			sessions = append(sessions, sessionInfo{
				ID:       fields[0],
				Hostname: hostname,
				IP:       ip,
			})
		} else if len(fields) >= 4 {
			sessions = append(sessions, sessionInfo{
				ID:       fields[0],
				Hostname: fields[3],
				IP:       fields[3],
			})
		}
	}
	return sessions
}

func stripSliverBanner(output string) string {
	lines := strings.Split(output, "\n")
	var clean []string
	for _, line := range lines {
		if strings.HasPrefix(line, "[*] ") {
			continue
		}
		clean = append(clean, line)
	}
	return strings.TrimSpace(strings.Join(clean, "\n"))
}
