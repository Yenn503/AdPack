package modules

import (
	"fmt"
	"strings"

	"adpack/core"
)

// ReconVerdict tells whether real-world tool output matched the executor's
// predicted delta well enough to trust the graph mutation.
type ReconVerdict struct {
	Trustworthy bool
	Mismatches  []ReconMismatch
	Confidence  float64
	Summary     string
}

// ReconMismatch records a single field-level discrepancy between predicted
// and actual outcome.
type ReconMismatch struct {
	Field    string
	Expected string
	Actual   string
}

// ReconcileCrossCheck takes an executor's predicted result, the capability
// that was executed, and the real tool output/exit code. The caller should
// only apply the delta when Trustworthy is true.
func ReconcileCrossCheck(predicted core.ExecutionResult, cap core.Capability, toolOutput string, exitCode int) ReconVerdict {
	if exitCode != 0 {
		return ReconVerdict{
			Trustworthy: false,
			Confidence:  0.0,
			Summary:     fmt.Sprintf("tool exit code %d", exitCode),
			Mismatches: []ReconMismatch{{
				Field: "exit_code", Expected: "0", Actual: fmt.Sprintf("%d", exitCode),
			}},
		}
	}
	if strings.TrimSpace(toolOutput) == "" {
		return ReconVerdict{
			Trustworthy: false,
			Confidence:  0.0,
			Summary:     "empty tool output",
			Mismatches: []ReconMismatch{{
				Field: "output", Expected: "non-empty", Actual: "(empty)",
			}},
		}
	}

	var mismatches []ReconMismatch
	outputLower := strings.ToLower(toolOutput)
	capLower := strings.ToLower(string(cap))

	// Check edge count: executor must produce deltas per system invariant
	if len(predicted.Delta.NewEdges) == 0 {
		mismatches = append(mismatches, ReconMismatch{
			Field: "edge_count", Expected: "at least 1", Actual: "0",
		})
	}

	// Validate tool output contains capability-specific success indicators
	switch {
	case strings.Contains(capLower, "add_member"):
		if !containsAny(outputLower, "group member", "added member", "added to group") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "group_member_added",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "force_change_password"):
		if !containsAny(outputLower, "password changed", "password set", "changed password") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "password_changed",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "write_dacl"):
		if !containsAny(outputLower, "object acl", "dacl", "write acl", "write dacl") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "acl_updated",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "generic_all"):
		if !containsAny(outputLower, "delegated", "rights delegated", "generic all") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "rights_delegated",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "dcsync"):
		if !containsAny(outputLower, "dumping domain", "password hash", "krbtgt", "samr") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "dcsync_completed",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "cert_auth"):
		if !containsAny(outputLower, "requested certificate", "saved certificate", ".pfx", "got tgt") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "certificate_issued",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "unconstrained_delegation"):
		// Confirmation that the captured TGT actually let us DCSync —
		// secretsdump prints "Dumping Domain Credentials" and the krbtgt
		// hash on success. Absence of either means no usable TGT yet.
		if !containsAny(outputLower, "dumping domain credentials", "krbtgt", "samr", "service rpc") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "dcsync_via_captured_tgt",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "kerberoast"):
		if !containsAny(outputLower, "krb5tgs", "tgs hash", "hashcat") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "kerberos_tgs_hash",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "asrep_roast"):
		if !containsAny(outputLower, "krb5asrep", "asrep", "hashcat") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "asrep_hash",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	case strings.Contains(capLower, "s4u_delegation"):
		// impacket-getST prints "Saving ticket in" + ".ccache" on success.
		// Failures usually contain "KDC_ERR_BADOPTION" or
		// "KDC_ERR_S_PRINCIPAL_UNKNOWN" which we treat as mismatch.
		if !containsAny(outputLower, "saving ticket in", ".ccache", "impersonating", "got tgs") {
			mismatches = append(mismatches, ReconMismatch{
				Field: "output_indicator", Expected: "tgs_obtained",
				Actual: fmt.Sprintf("no match in: %.200s", toolOutput),
			})
		}
	}

	if len(mismatches) > 0 {
		return ReconVerdict{
			Trustworthy: false,
			Mismatches:  mismatches,
			Confidence:  0.3,
			Summary:     fmt.Sprintf("%d mismatch(es)", len(mismatches)),
		}
	}

	return ReconVerdict{
		Trustworthy: true,
		Confidence:  0.85,
		Summary:     "reconciled — output matches predicted delta",
	}
}

func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
