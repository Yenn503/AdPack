package tools

import "fmt"

// ToolError is the canonical error type for tool execution failures.
// Tool name + operation + exit code + wrapped underlying error.
type ToolError struct {
	Tool     string
	Op       string
	Err      error
	ExitCode int
}

func (e *ToolError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s:%s exited %d: %v", e.Tool, e.Op, e.ExitCode, e.Err)
	}
	return fmt.Sprintf("%s:%s exited %d", e.Tool, e.Op, e.ExitCode)
}

func (e *ToolError) Unwrap() error { return e.Err }
