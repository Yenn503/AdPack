# Contributing to adpack

Guidelines for contributing code, docs, and bug reports.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/adpack.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit with clear messages
7. Push to your fork
8. Open a pull request

## Code Style

### Go Code

- Follow standard Go conventions and idioms
- Run `gofmt`, `go vet`, and `staticcheck` before committing
- Use meaningful variable and function names
- Keep functions focused and under 50 lines when possible

## Project Structure

```
adpack/
├── cmd/                    # CLI commands (one file per command)
├── core/                   # Domain models, interfaces (Transport, provider, identity)
├── modules/                # Attack phase implementations + provider layer
├── tools/                  # External tool wrappers (NetExec, nanodump, deploy)
├── storage/                # Database layer (SQLite, migrations, event persistence)
├── utils/                  # Shared utilities (command runner, theme, config)
├── tui/                    # Interactive bubbletea dashboard
├── config/                 # Configuration loading
├── internal/
│   ├── cracker/            # Hash cracking pipeline (queue, worker, materializer)
│   ├── executorbackend/    # Capability executors (ADCS, DCSync, RBCD, etc.)
│   ├── resolver/           # Artifact resolution pipeline (cert, shadowcred)
│   ├── runtime/            # Managed services (Responder, Relay, Coercer)
│   └── transport/          # Transport implementations (local SMB/WMI/WinRM)
└── planner/                # Attack path planning (Dijkstra over edge graph)
```

## Adding Features

### New Attack Phase

1. Add phase constant to `core/state.go`:
```go
const PhaseNewPhase Phase = "new_phase"
```

2. Wire into `core/state.go` dependency map and phase ordering

3. Create module in `modules/newphase.go` using tool wrappers

4. Add CLI command in `cmd/run.go`

### New Tool Wrapper

1. Create `tools/newtool.go` with a package-level singleton:
```go
type newTool struct{}

var NewTool = newTool{}

func (newTool) Name() string { return "newtool" }
func (newTool) Available() bool { return utils.ToolAvailable("newtool") }
func (newTool) Run(ctx context.Context, args []string) (utils.CmdResult, error) {
    return utils.RunCommandCtx(ctx, "newtool", args), nil
}
```

2. Import and use the singleton from modules or other tools:
```go
if tools.NewTool.Available() {
    result, err := tools.NewTool.Run(ctx, []string{"arg1", "arg2"})
}
```

### New Evasion Profile

1. Add to the profile map in `modules/evasion.go` via `registerProfile` and add to `AllProfiles()` list
2. Wire the profile name as a case in pipeline switching logic in `modules/credential_acq.go`
3. Register the profile in `BaseProfileFor()` mapping in `modules/evasion.go`
4. Create tool wrapper in `tools/` if it uses a new binary

## Testing

### Running Tests

```bash
go test ./...
```

### Writing Tests

- Place tests in `*_test.go` files
- Use table-driven tests for multiple cases
- Mock external dependencies
- Test error conditions

Example:

```go
func TestParseCredentials(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected int
    }{
        {"valid output", "Username: admin\nPassword: pass123", 1},
        {"empty output", "", 0},
        {"malformed", "invalid data", 0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := parseCredentials(tt.input)
            if len(result) != tt.expected {
                t.Errorf("got %d, want %d", len(result), tt.expected)
            }
        })
    }
}
```

## Documentation

### Code Comments

- Document all exported functions
- Explain complex algorithms
- Include usage examples for non-obvious code

### README Updates

- Update README.md when adding features
- Include examples for new commands
- Update configuration section for new options

## Pull Request Process

1. **Title**: Use clear, descriptive titles
   - Good: "Add Kerberoasting support to credential_acq module"
   - Bad: "Update code"

2. **Description**: Include:
   - What changed and why
   - How to test the changes
   - Any breaking changes
   - Related issues

3. **Checklist**:
   - [ ] Code follows project style
   - [ ] Tests pass
   - [ ] Documentation updated
   - [ ] No unnecessary dependencies added
   - [ ] Commit messages are clear

## Commit Messages

Use conventional commit format:

```
type(scope): brief description

Longer explanation if needed.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Maintenance tasks

Examples:
```
feat(modules): add Kerberoasting to credential_acq

Implements Kerberoasting attack using NetExec and GetUserSPNs.
Automatically detects servicePrincipalName attributes and requests
TGS tickets for offline cracking.

Fixes #45
```

## Code Review

All submissions require review. We look for:

- Code quality and readability
- Test coverage
- Documentation completeness
- Security considerations
- Performance implications

## Questions?

Open an issue for:
- Feature requests
- Bug reports
- Design discussions
- General questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
