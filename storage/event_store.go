package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"adpack/core"
)

func (db *DB) AppendEvent(evt core.Event) error {
	payload, err := json.Marshal(evt.Metadata)
	if err != nil {
		payload = []byte("{}")
	}
	_, err = db.Exec(
		`INSERT INTO events(campaign_id, trace_id, parent_id, type, class, source, payload, timestamp) VALUES(?,?,?,?,?,?,?,?)`,
		evt.CampaignID, evt.TraceID, "", string(evt.Type), int(evt.Class), evt.Source, string(payload), evt.Timestamp.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	return nil
}

func (db *DB) Replay(from time.Time) ([]core.Event, error) {
	rows, err := db.Query(
		`SELECT id, campaign_id, trace_id, type, class, source, payload, timestamp FROM events WHERE timestamp >= ? ORDER BY id`,
		from.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("replay query: %w", err)
	}
	defer rows.Close()

	var events []core.Event
	for rows.Next() {
		var (
			id         int
			campaignID string
			traceID    string
			typeStr    string
			classInt   int
			source     string
			payloadStr string
			tsStr      string
		)
		if err := rows.Scan(&id, &campaignID, &traceID, &typeStr, &classInt, &source, &payloadStr, &tsStr); err != nil {
			return nil, fmt.Errorf("replay scan: %w", err)
		}
		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			ts = time.Now()
		}
		metadata := make(map[string]any)
		if payloadStr != "" && payloadStr != "{}" {
			json.Unmarshal([]byte(payloadStr), &metadata)
		}
		events = append(events, core.Event{
			Type:       core.EventType(typeStr),
			Class:      core.EventClass(classInt),
			Source:     source,
			Timestamp:  ts,
			Metadata:   metadata,
			TraceID:    traceID,
			CampaignID: campaignID,
		})
	}
	return events, rows.Err()
}
