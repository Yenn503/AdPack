package adcs

import (
	"time"

	"adpack/core"
	"adpack/utils"
)

const CERT_ENROLL core.Capability = "ADCS_CERT_ENROLL"
const PKINIT_AUTH core.Capability = "ADCS_PKINIT_AUTH"

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
