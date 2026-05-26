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
	queue    *HashQueue
	hashcat  string
	wordlist string
}

func NewCrackWorker(queue *HashQueue, hashcatPath, wordlistPath string) *CrackWorker {
	return &CrackWorker{queue: queue, hashcat: hashcatPath, wordlist: wordlistPath}
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, w.hashcat, "-m", mode, "-a", "0",
		hashFile, w.wordlist, "--outfile", filepath.Join(dir, "found.txt"),
		"--potfile-disable", "--status", "-O")
	if err := cmd.Run(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return "", nil
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		show := exec.Command(w.hashcat, "-m", mode, "--show", hashFile, "--potfile-disable")
		out, err := show.Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return parts[1], nil
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	return "", nil
}

func hashcatMode(ht HashType) string {
	switch ht {
	case HashKRB5TGS:
		return "18200"
	case HashKRB5ASREP:
		return "18200"
	case HashNTLM:
		return "1000"
	}
	return ""
}
