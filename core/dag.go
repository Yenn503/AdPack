package core

import (
	"encoding/json"
	"time"
)

type NodeStatus string

const (
	NodePending  NodeStatus = "pending"
	NodeRunning  NodeStatus = "running"
	NodeSuccess  NodeStatus = "success"
	NodeFailed   NodeStatus = "failed"
	NodeCanceled NodeStatus = "cancelled"
)

type DAGNode struct {
	ID         string           `json:"id"`
	CampaignID string           `json:"campaign_id"`
	ParentID   string           `json:"parent_id"`
	Tool       string           `json:"tool"`
	Phase      Phase            `json:"phase"`
	Status     NodeStatus       `json:"status"`
	Attempt    int              `json:"attempt"`
	LastError  string           `json:"last_error,omitempty"`
	Input      json.RawMessage  `json:"input"`
	Output     json.RawMessage  `json:"output"`
	CreatedAt  time.Time        `json:"created_at"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

type DAGStore interface {
	SaveNode(n *DAGNode) error
	UpdateNodeStatus(id string, status NodeStatus, output json.RawMessage, lastErr string) error
	LoadNodes(campaignID string) ([]DAGNode, error)
	LoadNode(id string) (*DAGNode, error)
	LoadChildren(parentID string) ([]DAGNode, error)
}
