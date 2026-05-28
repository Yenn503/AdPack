package core

type HostExecutionStatus string

const (
	HostPending HostExecutionStatus = "pending"
	HostRunning HostExecutionStatus = "running"
	HostDone    HostExecutionStatus = "done"
	HostFailed  HostExecutionStatus = "failed"
)

type PhaseExecution struct {
	Phase    Phase
	Hosts    map[string]HostExecutionStatus
	Complete bool
}

func NewPhaseExecution(phase Phase) *PhaseExecution {
	return &PhaseExecution{
		Phase: phase,
		Hosts: make(map[string]HostExecutionStatus),
	}
}

func (pe *PhaseExecution) MarkDone(ip string) {
	pe.Hosts[ip] = HostDone
}

func (pe *PhaseExecution) MarkFailed(ip string) {
	pe.Hosts[ip] = HostFailed
}

func (pe *PhaseExecution) MarkRunning(ip string) {
	pe.Hosts[ip] = HostRunning
}

func (pe *PhaseExecution) SkippedHosts() []string {
	var skipped []string
	for ip, st := range pe.Hosts {
		if st == HostDone {
			skipped = append(skipped, ip)
		}
	}
	return skipped
}

func (pe *PhaseExecution) PendingHosts() []string {
	var pending []string
	for ip, st := range pe.Hosts {
		if st == HostPending || st == HostFailed {
			pending = append(pending, ip)
		}
	}
	return pending
}
