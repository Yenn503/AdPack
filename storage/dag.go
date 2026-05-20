package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"adpack/core"
)

const nodeCols = `id, campaign_id, parent_id, tool, phase, status, attempt, last_error, input, output, created_at, started_at, finished_at`

func scanNode(scanner interface {
	Scan(dest ...any) error
}) (core.DAGNode, error) {
	var (
		id, campaign, parentID, tool, phase, status string
		attempt                                     int
		lastError                                   string
		inputStr, outputStr, createdStr, startedStr string
		finishedStr                                 *string
	)
	err := scanner.Scan(&id, &campaign, &parentID, &tool, &phase, &status, &attempt, &lastError, &inputStr, &outputStr, &createdStr, &startedStr, &finishedStr)
	if err != nil {
		return core.DAGNode{}, err
	}
	created, _ := time.Parse(time.RFC3339, createdStr)
	started, _ := time.Parse(time.RFC3339, startedStr)
	n := core.DAGNode{
		ID:         id,
		CampaignID: campaign,
		ParentID:   parentID,
		Tool:       tool,
		Phase:      core.Phase(phase),
		Status:     core.NodeStatus(status),
		Attempt:    attempt,
		LastError:  lastError,
		Input:      json.RawMessage(inputStr),
		Output:     json.RawMessage(outputStr),
		CreatedAt:  created,
		StartedAt:  started,
	}
	if finishedStr != nil {
		t, err := time.Parse(time.RFC3339, *finishedStr)
		if err == nil {
			n.FinishedAt = &t
		}
	}
	return n, nil
}

func nodeArgs(n *core.DAGNode) []any {
	var finishedAt *string
	if n.FinishedAt != nil {
		s := n.FinishedAt.Format(time.RFC3339)
		finishedAt = &s
	}
	return []any{
		n.ID, n.CampaignID, n.ParentID, n.Tool, string(n.Phase), string(n.Status),
		n.Attempt, n.LastError,
		string(n.Input), string(n.Output),
		n.CreatedAt.Format(time.RFC3339), n.StartedAt.Format(time.RFC3339), finishedAt,
	}
}

func (db *DB) SaveNode(n *core.DAGNode) error {
	_, err := db.Exec(
		`INSERT INTO execution_nodes(`+nodeCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nodeArgs(n)...,
	)
	if err != nil {
		return fmt.Errorf("save node: %w", err)
	}
	if n.ParentID != "" {
		_, err = db.Exec(
			`INSERT OR IGNORE INTO execution_edges(parent_id, child_id) VALUES(?,?)`,
			n.ParentID, n.ID,
		)
		if err != nil {
			return fmt.Errorf("save edge: %w", err)
		}
	}
	return nil
}

func (db *DB) UpdateNodeStatus(id string, status core.NodeStatus, output json.RawMessage, lastErr string) error {
	outputJSON, _ := json.Marshal(output)
	now := time.Now().Format(time.RFC3339)
	terminal := status == core.NodeSuccess || status == core.NodeFailed || status == core.NodeCanceled
	q := `UPDATE execution_nodes SET status=?, output=?, last_error=?, started_at=?`
	args := []any{string(status), string(outputJSON), lastErr, now}
	if status == core.NodeFailed {
		q += `, attempt=attempt+1`
	}
	if terminal {
		q += `, finished_at=?`
		args = append(args, now)
	}
	q += ` WHERE id=?`
	args = append(args, id)
	if _, err := db.Exec(q, args...); err != nil {
		return fmt.Errorf("update node: %w", err)
	}
	return nil
}

func (db *DB) LoadNodes(campaignID string) ([]core.DAGNode, error) {
	rows, err := db.Query(
		`SELECT `+nodeCols+` FROM execution_nodes WHERE campaign_id=? ORDER BY started_at`,
		campaignID,
	)
	if err != nil {
		return nil, fmt.Errorf("load nodes: %w", err)
	}
	defer rows.Close()

	var nodes []core.DAGNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (db *DB) LoadNode(id string) (*core.DAGNode, error) {
	row := db.QueryRow(`SELECT `+nodeCols+` FROM execution_nodes WHERE id=?`, id)
	n, err := scanNode(row)
	if err != nil {
		return nil, fmt.Errorf("load node %s: %w", id, err)
	}
	return &n, nil
}

func (db *DB) LoadChildren(parentID string) ([]core.DAGNode, error) {
	rows, err := db.Query(
		`SELECT n.`+nodeCols+`
		 FROM execution_nodes n
		 JOIN execution_edges e ON e.child_id = n.id
		 WHERE e.parent_id = ?
		 ORDER BY n.started_at`,
		parentID,
	)
	if err != nil {
		return nil, fmt.Errorf("load children: %w", err)
	}
	defer rows.Close()

	var nodes []core.DAGNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, fmt.Errorf("scan child: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}
