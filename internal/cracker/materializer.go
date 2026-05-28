package cracker

type CrackedCredential struct {
	Username string
	Domain   string
	Secret   string
	Hash     string
	HashType HashType
}

type CredentialMaterializer struct {
	queue     *HashQueue
	onCracked func(CrackedCredential)
}

func NewCredentialMaterializer(queue *HashQueue, onCracked func(CrackedCredential)) *CredentialMaterializer {
	return &CredentialMaterializer{queue: queue, onCracked: onCracked}
}

func (m *CredentialMaterializer) Run() {
	for event := range m.queue.Events() {
		if event.Type != "crack_complete" || event.Error != nil {
			continue
		}
		if event.Result == "" || event.Job == nil {
			continue
		}
		cred := CrackedCredential{
			Username: event.Job.Username,
			Domain:   event.Job.Domain,
			Secret:   event.Result,
			Hash:     event.Job.Hash,
			HashType: event.Job.HashType,
		}
		m.onCracked(cred)
	}
}
