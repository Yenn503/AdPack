package cracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CrackWorker struct {
	queue        *HashQueue
	hashcat      string
	wordlist     string
	rules        []string
	crackTimeout time.Duration
}

func NewCrackWorker(queue *HashQueue, hashcatPath, wordlistPath string, rules []string, timeout time.Duration) *CrackWorker {
	return &CrackWorker{queue: queue, hashcat: hashcatPath, wordlist: wordlistPath, rules: rules, crackTimeout: timeout}
}

func (w *CrackWorker) Run() {
	for {
		job := w.queue.Dequeue()
		if job == nil {
			time.Sleep(time.Second)
			continue
		}
		result, err := w.crack(job)
		if err != nil {
			w.queue.events <- CrackEvent{Type: "crack_complete", Job: job, Error: err}
			continue
		}
		if result == "" {
			continue
		}
		w.queue.events <- CrackEvent{Type: "crack_complete", Job: job, Result: result}
	}
}

func (w *CrackWorker) crack(job *CrackJob) (string, error) {
	dir, err := os.MkdirTemp("", "adpack-crack-*")
	if err != nil {
		return "", fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	hashFile := filepath.Join(dir, "hash.txt")
	if err := os.WriteFile(hashFile, []byte(job.Hash+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write hash: %w", err)
	}

	mode := hashcatMode(job.HashType)
	if mode == "" {
		return "", fmt.Errorf("unknown hash type: %s", job.HashType)
	}

	ctx, cancel := context.WithTimeout(context.Background(), w.crackTimeout)
	defer cancel()

	foundFile := filepath.Join(dir, "found.txt")
	args := []string{"-m", mode, "-a", "0",
		hashFile, w.wordlist,
		"--outfile", foundFile, "--outfile-format", "2",
		"--potfile-disable",
		"--status", "--status-timer", "1",
		"-O", "-w", "3",
		"--self-test-disable"}
	for _, rule := range w.rules {
		args = append(args, "-r", rule)
	}
	cmd := exec.CommandContext(ctx, w.hashcat, args...)
	if err := cmd.Run(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return "", nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("hashcat: %w", err)
	}

	out, err := os.ReadFile(foundFile)
	if err == nil {
		line := strings.TrimSpace(string(out))
		if line != "" {
			return line, nil
		}
	}

	return "", nil
}

func hashcatMode(ht HashType) string {
	switch ht {
	case HashKRB5TGS:
		return "13100"
	case HashKRB5ASREP:
		return "18200"
	case HashNTLM:
		return "1000"
	}
	return ""
}
