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
- Run `gofmt` before committing
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions focused and under 50 lines when possible

### Example

```go
// EnumUsers retrieves all domain users via LDAP
func (n nxcTool) EnumUsers(ctx context.Context, target string) ([]core.User, error) {
    r := utils.RunCommandCtx(ctx, "netexec", []string{"ldap", target, "--users"})
    if !r.Success {
        return nil, fmt.Errorf("netexec ldap enum failed: %s", r.Stderr)
    }
    // Parse output...
}
```

## Project Structure

```
adpack/
├── cmd/           # CLI commands (one file per command)
├── core/          # Domain models, interfaces (EventBus, DAGStore, EventStore)
├── engine/        # Runtime container, WorkerPool, orchestration wiring
├── modules/       # Attack phase implementations
├── tools/         # External tool wrappers + Registry + ExecutorFactory
├── storage/       # Database layer (SQLite, migrations, DAG/event persistence)
├── utils/         # Shared utilities (command runner, theme, config)
├── tui/           # Interactive bubbletea dashboard
└── config/        # Configuration management
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

1. Create `tools/newtool.go` implementing the `Tool` interface:
```go
type newTool struct{}

func (newTool) Name() string { return "newtool" }
func (newTool) Available() bool { return utils.ToolAvailable("newtool") }
func (newTool) Run(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
    r := utils.RunCommandCtx(ctx, "newtool", req.Args)
    return cmdResultToExecResult(r, ""), nil
}
func (newTool) RunStream(ctx context.Context, req ExecutionRequest) (<-chan StreamOutput, error) {
    return RunStreamBlocking(ctx, req, newTool{})
}
func (newTool) Validate(ctx context.Context) error { return nil }
func (newTool) Capabilities() []Capability { return nil }
```

2. Register in `tools/bootstrap.go`:
```go
func RegisterBuiltinTools(r *Registry) {
    // ...
    r.Register("newtool", newTool{})
}
```

### New Evasion Profile

1. Add to `modules/credential_acq.go` pipeline map:
```go
"profile_name": {
    Name:        "profile_name",
    Delivery:    "exe",
    PayloadType: "tool_name",
    RemoteExec:  true,
    ParseFn:     parseOutput,
    Description: "Profile description",
}
```

2. Implement execution function referencing tool wrappers by name

3. Register new Tool in `tools/bootstrap.go` if it uses a new binary

## Testing

### Running Tests

```bash
make test
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
