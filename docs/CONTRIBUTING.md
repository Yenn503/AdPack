# Contributing to AdPack

Development guidelines and contribution process.

## Development Environment

- Go 1.25+
- Linux or WSL2 (primary target platform)
- Git for version control

```bash
git clone https://github.com/Yenn503/AdPack.git
cd adpack
go mod download
go build -o adpack .
```

## Project Structure

```
adpack/
  cmd/            # CLI commands — one file per command group
  config/         # YAML config loading and validation
  core/           # Domain model — no external dependencies beyond stdlib + lipgloss
  internal/       # Internal packages — not importable externally
    bloodhound/   # BloodHound integration
    cracker/      # Hashcat cracking pipeline
    executorbackend/  # Capability executors (one package per technique)
    resolver/     # Identity resolution
    runtime/      # Process supervision
    transport/    # Transport layer (local, proxy, sliver)
  modules/        # Attack modules — orchestration logic
  planner/        # Attack path planning
  storage/        # SQLite persistence
  tools/          # External tool wrappers
  tui/            # Terminal UI (Bubble Tea)
  utils/          # Shared utilities (theme, command execution, logging)
```

## Code Style

- Standard Go formatting (`gofmt`, `goimports`)
- No comments or documentation in code unless explicitly required
- Imports grouped: stdlib, third-party, internal
- Error handling: always wrap errors with context using `fmt.Errorf("context: %w", err)`
- Use `adpack/utils` styled output helpers (`Step`, `StepOk`, `StepWarn`, `StepInfo`) instead of raw `fmt.Println`
- Concurrency: use `sync.RWMutex` for shared state, `defer recover()` in goroutines

## Adding a New Command

1. Create `cmd/<command>.go` with cobra command definition
2. Create `modules/<module>.go` with implementation logic
3. Register the command in `cmd/<command>.go` `init()` function
4. Add to README.md command table
5. Add to docs/USAGE.md

Example command structure:
```go
package cmd

import (
    "adpack/modules"
    "github.com/spf13/cobra"
)

var myCmd = &cobra.Command{
    Use:   "mycommand",
    Short: "Description",
    RunE: func(cmd *cobra.Command, args []string) error {
        return (&modules.MyModule{}).DoSomething(flag1, flag2)
    },
}

func init() {
    myCmd.Flags().StringVar(&flag1, "flag1", "", "Description")
    rootCmd.AddCommand(myCmd)
}
```

## Adding a New Transport

1. Create `internal/transport/<name>/<name>.go`
2. Implement the `core.Transport` interface:
   - `Exec(ctx, target, command) (string, error)`
   - `Upload(ctx, target, localPath, remotePath) error`
   - `Download(ctx, target, remotePath, localPath) error`
3. Wire into `cmd/root.go` `TransportFactory`

## Adding a New Capability Executor

1. Create `internal/executorbackend/<name>/<name>.go`
2. Implement the executor interface from `core/capability.go`
3. Register in `cmd/root.go` `init()` via `CapabilityRegistry.Register()`

## Testing

```bash
go test ./...                    # Run all tests
go test -v ./modules/            # Verbose module tests
go test -race ./...              # Race detection
go vet ./...                     # Static analysis
```

Test files follow Go convention: `<name>_test.go` alongside the source file.

## Before Submitting

1. Run `go build -o adpack .` — must compile clean
2. Run `go vet ./...` — no warnings
3. Run `go test ./...` — all tests pass
4. Update documentation if adding/changing commands
5. Update CHANGELOG.md under an `Unreleased` section

## Commit Guidelines

- Atomic commits — one logical change per commit
- Descriptive commit messages
- No binary files in commits (use .gitignore patterns)

## Release Process

1. Update version in `cmd/root.go` (`version` variable)
2. Update version badge in README.md
3. Move `Unreleased` changes to a new version section in CHANGELOG.md
4. Tag: `git tag v0.X.0`
5. Build: `go build -o adpack .`

## Security Considerations

- Never hardcode credentials or API keys
- Use `0600` permissions for files containing secrets
- Validate all user input (session names, file paths, target IPs)
- Use `exec.Command` (not shell) for external tool execution where possible
- PowerShell command injection: use encoded commands or temp file uploads for complex scripts
- Session export files: always use restrictive permissions (`0600`)
