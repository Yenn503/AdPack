package cracker

import "time"

type HashType string

const (
	HashKRB5TGS   HashType = "krb5tgs"
	HashKRB5ASREP HashType = "krb5asrep"
	HashNTLM      HashType = "ntlm"
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
	Type   string
	Job    *CrackJob
	Result string
	Error  error
}
