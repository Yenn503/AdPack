package core

import (
	"testing"
)

func TestExecutionResult_Success(t *testing.T) {
	r := ExecutionResult{FailureMode: FailureSuccess}
	if !r.Success() {
		t.Fatal("expected Success() = true for FailureSuccess")
	}
}

func TestExecutionResult_NotSuccess(t *testing.T) {
	r := ExecutionResult{FailureMode: FailureRetryable}
	if r.Success() {
		t.Fatal("expected Success() = false for non-success failure mode")
	}
}
