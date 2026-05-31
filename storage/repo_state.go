package storage

import (
	"adpack/core"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// edgeRow is the on-disk representation of a core.PrivilegeEdge.
// Slice fields are JSON-encoded; timestamps are RFC3339 strings so they
// round-trip through SQLite's TEXT affinity without lossy formats.
type edgeRow struct {
	ID                 int     `db:"id"`
	SourcePrincipal    string  `db:"source_principal"`
	TargetPrincipal    string  `db:"target_principal"`
	AccessRight        string  `db:"access_right"`
	EdgeType           string  `db:"edge_type"`
	Domain             string  `db:"domain"`
	Source             string  `db:"source"`
	Confidence         float64 `db:"confidence"`
	Weight             float64 `db:"weight"`
	Exploitability     float64 `db:"exploitability"`
	Noise              float64 `db:"noise"`
	RequiresJSON       string  `db:"requires_json"`
	ValidationState    string  `db:"validation_state"`
	ObservedAt         string  `db:"observed_at"`
	ObservedBy         string  `db:"observed_by"`
	PreconditionsJSON  string  `db:"preconditions_json"`
	Provenance         string  `db:"provenance"`
	LastVerifiedAt     string  `db:"last_verified_at"`
	VerificationMethod string  `db:"verification_method"`
}

func edgeToRow(e core.PrivilegeEdge) (edgeRow, error) {
	reqJSON := "[]"
	if len(e.Requires) > 0 {
		b, err := json.Marshal(e.Requires)
		if err != nil {
			return edgeRow{}, fmt.Errorf("marshal requires: %w", err)
		}
		reqJSON = string(b)
	}
	preJSON := "[]"
	if len(e.Preconditions) > 0 {
		b, err := json.Marshal(e.Preconditions)
		if err != nil {
			return edgeRow{}, fmt.Errorf("marshal preconditions: %w", err)
		}
		preJSON = string(b)
	}
	state := string(e.ValidationState)
	if state == "" {
		state = string(core.EdgeInferred)
	}
	obs := ""
	if !e.ObservedAt.IsZero() {
		obs = e.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	lv := ""
	if !e.LastVerifiedAt.IsZero() {
		lv = e.LastVerifiedAt.UTC().Format(time.RFC3339Nano)
	}
	return edgeRow{
		SourcePrincipal:    e.SourcePrincipal,
		TargetPrincipal:    e.TargetPrincipal,
		AccessRight:        e.AccessRight,
		EdgeType:           e.EdgeType,
		Domain:             e.Domain,
		Source:             e.Source,
		Confidence:         e.Confidence,
		Weight:             e.Weight,
		Exploitability:     e.Exploitability,
		Noise:              e.Noise,
		RequiresJSON:       reqJSON,
		ValidationState:    state,
		ObservedAt:         obs,
		ObservedBy:         e.ObservedBy,
		PreconditionsJSON:  preJSON,
		Provenance:         e.Provenance,
		LastVerifiedAt:     lv,
		VerificationMethod: e.VerificationMethod,
	}, nil
}

func rowToEdge(r edgeRow) (core.PrivilegeEdge, error) {
	var req []string
	if r.RequiresJSON != "" && r.RequiresJSON != "[]" {
		if err := json.Unmarshal([]byte(r.RequiresJSON), &req); err != nil {
			return core.PrivilegeEdge{}, fmt.Errorf("unmarshal requires: %w", err)
		}
	}
	var pre []core.ExecutionPrecondition
	if r.PreconditionsJSON != "" && r.PreconditionsJSON != "[]" {
		if err := json.Unmarshal([]byte(r.PreconditionsJSON), &pre); err != nil {
			return core.PrivilegeEdge{}, fmt.Errorf("unmarshal preconditions: %w", err)
		}
	}
	parseTime := func(s string) time.Time {
		if s == "" {
			return time.Time{}
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t
		}
		return time.Time{}
	}
	return core.PrivilegeEdge{
		ID:                 r.ID,
		SourcePrincipal:    r.SourcePrincipal,
		TargetPrincipal:    r.TargetPrincipal,
		AccessRight:        r.AccessRight,
		EdgeType:           r.EdgeType,
		Domain:             r.Domain,
		Source:             r.Source,
		Confidence:         r.Confidence,
		Weight:             r.Weight,
		Exploitability:     r.Exploitability,
		Noise:              r.Noise,
		Requires:           req,
		ValidationState:    core.EdgeValidationState(r.ValidationState),
		ObservedAt:         parseTime(r.ObservedAt),
		ObservedBy:         r.ObservedBy,
		Preconditions:      pre,
		Provenance:         r.Provenance,
		LastVerifiedAt:     parseTime(r.LastVerifiedAt),
		VerificationMethod: r.VerificationMethod,
	}, nil
}

const edgeUpsertSQL = `INSERT INTO edges(
		source_principal,target_principal,access_right,edge_type,domain,source,
		confidence,weight,exploitability,noise,requires_json,validation_state,
		observed_at,observed_by,preconditions_json,provenance,last_verified_at,verification_method
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(source_principal,target_principal,access_right,edge_type,domain) DO UPDATE SET
		source=excluded.source,
		confidence=excluded.confidence,
		weight=excluded.weight,
		exploitability=excluded.exploitability,
		noise=excluded.noise,
		requires_json=excluded.requires_json,
		validation_state=excluded.validation_state,
		observed_at=excluded.observed_at,
		observed_by=excluded.observed_by,
		preconditions_json=excluded.preconditions_json,
		provenance=excluded.provenance,
		last_verified_at=excluded.last_verified_at,
		verification_method=excluded.verification_method`

// SaveEdge upserts a single privilege edge.
func (db *DB) SaveEdge(e core.PrivilegeEdge) error {
	r, err := edgeToRow(e)
	if err != nil {
		return err
	}
	_, err = db.Exec(edgeUpsertSQL,
		r.SourcePrincipal, r.TargetPrincipal, r.AccessRight, r.EdgeType, r.Domain, r.Source,
		r.Confidence, r.Weight, r.Exploitability, r.Noise, r.RequiresJSON, r.ValidationState,
		r.ObservedAt, r.ObservedBy, r.PreconditionsJSON, r.Provenance, r.LastVerifiedAt, r.VerificationMethod,
	)
	return err
}

// SaveEdges upserts each edge inside a single transaction.
func (db *DB) SaveEdges(ee []core.PrivilegeEdge) error {
	if len(ee) == 0 {
		return nil
	}
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("save edges begin: %w", err)
	}
	defer tx.Rollback()
	stmt, err := tx.Preparex(edgeUpsertSQL)
	if err != nil {
		return fmt.Errorf("save edges prepare: %w", err)
	}
	for _, e := range ee {
		r, err := edgeToRow(e)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(
			r.SourcePrincipal, r.TargetPrincipal, r.AccessRight, r.EdgeType, r.Domain, r.Source,
			r.Confidence, r.Weight, r.Exploitability, r.Noise, r.RequiresJSON, r.ValidationState,
			r.ObservedAt, r.ObservedBy, r.PreconditionsJSON, r.Provenance, r.LastVerifiedAt, r.VerificationMethod,
		); err != nil {
			return fmt.Errorf("save edge %s→%s: %w", e.SourcePrincipal, e.TargetPrincipal, err)
		}
	}
	return tx.Commit()
}

// LoadEdges returns all persisted privilege edges.
func (db *DB) LoadEdges() ([]core.PrivilegeEdge, error) {
	var rows []edgeRow
	if err := db.Select(&rows, "SELECT * FROM edges"); err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}
	out := make([]core.PrivilegeEdge, 0, len(rows))
	for _, r := range rows {
		e, err := rowToEdge(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ClearEdges deletes all rows from the edges table. Used by `adpack reset`.
func (db *DB) ClearEdges() error {
	_, err := db.Exec("DELETE FROM edges")
	return err
}

func (db *DB) SaveHost(h core.Host) error {
	_, err := db.Exec(`INSERT INTO hosts(ip,hostname,domain,os,is_dc,ports_open,discovery_src,edr,evasion_hist) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,domain=excluded.domain,os=excluded.os,is_dc=excluded.is_dc,ports_open=excluded.ports_open,edr=excluded.edr,evasion_hist=excluded.evasion_hist`,
		h.IP, h.Hostname, h.Domain, h.OS, boolInt(h.IsDC), h.PortsOpen, h.DiscoverySrc, h.EDR, h.EvasionHist)
	return err
}
func (db *DB) SaveHosts(hh []core.Host) error {
	for _, h := range hh {
		if err := db.SaveHost(h); err != nil {
			return err
		}
	}
	return nil
}
func (db *DB) LoadHosts() ([]core.Host, error) {
	var hh []core.Host
	err := db.Select(&hh, "SELECT * FROM hosts")
	return hh, err
}

func (db *DB) SaveUser(u core.User) error {
	_, err := db.Exec(`INSERT INTO users(username,domain,sam_account_name,sid,enabled,is_admin,is_da,description,source,no_preauth,spns) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(username, domain) DO UPDATE SET sam_account_name=excluded.sam_account_name,sid=excluded.sid,enabled=excluded.enabled,is_admin=excluded.is_admin,is_da=excluded.is_da,description=excluded.description,source=excluded.source,no_preauth=excluded.no_preauth,spns=excluded.spns`,
		u.Username, u.Domain, u.SAMAccountName, u.SID, boolInt(u.Enabled), boolInt(u.IsAdmin), boolInt(u.IsDA), u.Description, u.Source, boolInt(u.NoPreauth), u.SPNs)
	return err
}
func (db *DB) SaveUsers(uu []core.User) error {
	for _, u := range uu {
		if err := db.SaveUser(u); err != nil {
			return err
		}
	}
	return nil
}
func (db *DB) LoadUsers() ([]core.User, error) {
	var uu []core.User
	err := db.Select(&uu, "SELECT * FROM users")
	return uu, err
}

func (db *DB) SaveCred(c core.Credential) error {
	// Encrypt sensitive fields
	encSecret, err := db.Encrypt(c.Secret)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}
	encHash, err := db.Encrypt(c.Hash)
	if err != nil {
		return fmt.Errorf("encrypt hash: %w", err)
	}

	// Trust-preserving UPSERT: if the existing row is already validated
	// and the incoming row is *not* validated, keep the existing
	// secret/hash/source. Otherwise the new row wins. This prevents a
	// scraped-from-description credential (Validated=false) from
	// overwriting a manually-seeded or AS-REP/Kerberoast-cracked one
	// (Validated=true) and silently breaking every downstream tool call.
	_, err = db.Exec(`INSERT INTO credentials(type,username,domain,secret,hash,target,validated,source,source_tool,target_account,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(type, username, domain, target) DO UPDATE SET
			secret    = CASE WHEN credentials.validated = 1 AND excluded.validated = 0 THEN credentials.secret    ELSE excluded.secret    END,
			hash      = CASE WHEN credentials.validated = 1 AND excluded.validated = 0 THEN credentials.hash      ELSE excluded.hash      END,
			source    = CASE WHEN credentials.validated = 1 AND excluded.validated = 0 THEN credentials.source    ELSE excluded.source    END,
			validated = CASE WHEN credentials.validated = 1                            THEN 1                     ELSE excluded.validated END,
			source_tool    = excluded.source_tool,
			target_account = excluded.target_account,
			confidence     = excluded.confidence`,
		c.Type, c.Username, c.Domain, encSecret, encHash, c.Target, boolInt(c.Validated), c.Source,
		c.SourceTool, c.TargetAccount, c.Confidence)
	return err
}
func (db *DB) SaveCreds(cc []core.Credential) error {
	for _, c := range cc {
		if err := db.SaveCred(c); err != nil {
			return err
		}
	}
	return nil
}
func (db *DB) LoadCreds() ([]core.Credential, error) {
	var cc []core.Credential
	err := db.Select(&cc, "SELECT * FROM credentials")
	if err != nil {
		return nil, err
	}

	// Decrypt sensitive fields
	for i := range cc {
		if cc[i].Secret != "" {
			decSecret, err := db.Decrypt(cc[i].Secret)
			if err != nil {
				return nil, fmt.Errorf("decrypt secret for %s@%s: %w", cc[i].Username, cc[i].Domain, err)
			}
			// Defensive check: if decrypt returned the ciphertext unchanged, treat as error
			if decSecret == cc[i].Secret && strings.HasPrefix(cc[i].Secret, "v1:") {
				return nil, fmt.Errorf("decrypt secret for %s@%s: decryption returned ciphertext unchanged", cc[i].Username, cc[i].Domain)
			}
			cc[i].Secret = decSecret
		}
		if cc[i].Hash != "" {
			decHash, err := db.Decrypt(cc[i].Hash)
			if err != nil {
				return nil, fmt.Errorf("decrypt hash for %s@%s: %w", cc[i].Username, cc[i].Domain, err)
			}
			// Defensive check: if decrypt returned the ciphertext unchanged, treat as error
			if decHash == cc[i].Hash && strings.HasPrefix(cc[i].Hash, "v1:") {
				return nil, fmt.Errorf("decrypt hash for %s@%s: decryption returned ciphertext unchanged", cc[i].Username, cc[i].Domain)
			}
			cc[i].Hash = decHash
		}
	}

	return cc, nil
}

func (db *DB) SavePhases(state *core.ADState) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for p, s := range state.Phases {
		reason := string(state.SkipReasons[p])
		_, err := tx.Exec(`INSERT INTO phase_status(phase,status,skip_reason) VALUES(?,?,?) ON CONFLICT(phase) DO UPDATE SET status=excluded.status,skip_reason=excluded.skip_reason`, string(p), int(s), reason)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (db *DB) LoadPhases(state *core.ADState) (map[core.Phase]core.PhaseStatus, error) {
	type row struct {
		Phase      string `db:"phase"`
		Status     int    `db:"status"`
		SkipReason string `db:"skip_reason"`
	}
	var rows []row
	err := db.Select(&rows, "SELECT * FROM phase_status")
	if err != nil {
		return nil, err
	}
	m := make(map[core.Phase]core.PhaseStatus)
	for _, r := range rows {
		m[core.Phase(r.Phase)] = core.PhaseStatus(r.Status)
		if r.SkipReason != "" {
			state.SkipReasons[core.Phase(r.Phase)] = core.SkipReason(r.SkipReason)
		}
	}
	return m, nil
}

func (db *DB) LoadGroups() ([]core.Group, error) {
	var gg []core.Group
	err := db.Select(&gg, "SELECT * FROM groups_t")
	return gg, err
}

func (db *DB) LoadComputers() ([]core.Computer, error) {
	var cc []core.Computer
	err := db.Select(&cc, "SELECT * FROM computers")
	return cc, err
}

func (db *DB) LoadSessions() ([]core.Session, error) {
	var ss []core.Session
	err := db.Select(&ss, "SELECT * FROM sessions")
	return ss, err
}

func (db *DB) LoadGPOs() ([]core.GPO, error) {
	var gg []core.GPO
	err := db.Select(&gg, "SELECT * FROM gpos")
	return gg, err
}

func (db *DB) LoadADCSTemplates() ([]core.ADCSTemplate, error) {
	var tt []core.ADCSTemplate
	err := db.Select(&tt, "SELECT * FROM adcs_templates")
	return tt, err
}

func (db *DB) SaveBH(m core.BloodhoundMeta) error {
	_, err := db.Exec(`UPDATE bloodhound_meta SET collected=?,ingested=?,file_path=?,da_users=?,da_count=?,outbound_trust=? WHERE id=1`,
		boolInt(m.Collected), boolInt(m.Ingested), m.FilePath, m.DAUsers, m.DACount, boolInt(m.OutboundTrust))
	return err
}
func (db *DB) LoadBH() (core.BloodhoundMeta, error) {
	var m core.BloodhoundMeta
	err := db.Get(&m, "SELECT * FROM bloodhound_meta WHERE id=1")
	return m, err
}

func (db *DB) SaveState(s *core.ADState) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("save state begin: %w", err)
	}
	defer tx.Rollback()

	stmtHost, err := tx.Preparex(`INSERT INTO hosts(ip,hostname,domain,os,is_dc,ports_open,discovery_src,edr,evasion_hist) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname,domain=excluded.domain,os=excluded.os,is_dc=excluded.is_dc,ports_open=excluded.ports_open,edr=excluded.edr,evasion_hist=excluded.evasion_hist`)
	if err != nil {
		return err
	}
	for _, h := range s.Hosts {
		if _, err := stmtHost.Exec(h.IP, h.Hostname, h.Domain, h.OS, boolInt(h.IsDC), h.PortsOpen, h.DiscoverySrc, h.EDR, h.EvasionHist); err != nil {
			return err
		}
	}

	stmtUser, err := tx.Preparex(`INSERT INTO users(username,domain,sam_account_name,sid,enabled,is_admin,is_da,description,source,no_preauth,spns) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(username, domain) DO UPDATE SET sam_account_name=excluded.sam_account_name,sid=excluded.sid,enabled=excluded.enabled,is_admin=excluded.is_admin,is_da=excluded.is_da,description=excluded.description,source=excluded.source,no_preauth=excluded.no_preauth,spns=excluded.spns`)
	if err != nil {
		return err
	}
	for _, u := range s.Users {
		if _, err := stmtUser.Exec(u.Username, u.Domain, u.SAMAccountName, u.SID, boolInt(u.Enabled), boolInt(u.IsAdmin), boolInt(u.IsDA), u.Description, u.Source, boolInt(u.NoPreauth), u.SPNs); err != nil {
			return err
		}
	}

	stmtCred, err := tx.Preparex(`INSERT INTO credentials(type,username,domain,secret,hash,target,validated,source,source_tool,target_account,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(type, username, domain, target) DO UPDATE SET secret=excluded.secret,hash=excluded.hash,validated=excluded.validated,source=excluded.source,source_tool=excluded.source_tool,target_account=excluded.target_account,confidence=excluded.confidence`)
	if err != nil {
		return err
	}
	for _, c := range s.Creds {
		// Encrypt sensitive fields
		encSecret, err := db.Encrypt(c.Secret)
		if err != nil {
			return fmt.Errorf("encrypt secret: %w", err)
		}
		encHash, err := db.Encrypt(c.Hash)
		if err != nil {
			return fmt.Errorf("encrypt hash: %w", err)
		}

		if _, err := stmtCred.Exec(c.Type, c.Username, c.Domain, encSecret, encHash, c.Target, boolInt(c.Validated), c.Source, c.SourceTool, c.TargetAccount, c.Confidence); err != nil {
			return err
		}
	}

	stmtGroup, err := tx.Preparex(`INSERT INTO groups_t(name,domain,sid,description,member_count) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET sid=excluded.sid,description=excluded.description,member_count=excluded.member_count`)
	if err != nil {
		return err
	}
	for _, g := range s.Groups {
		if _, err := stmtGroup.Exec(g.Name, g.Domain, g.SID, g.Description, g.MemberCount); err != nil {
			return err
		}
	}

	stmtComputer, err := tx.Preparex(`INSERT INTO computers(name,domain,sid,operating_system,is_dc) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET sid=excluded.sid,operating_system=excluded.operating_system,is_dc=excluded.is_dc`)
	if err != nil {
		return err
	}
	for _, c := range s.Computers {
		if _, err := stmtComputer.Exec(c.Name, c.Domain, c.SID, c.OperatingSystem, boolInt(c.IsDC)); err != nil {
			return err
		}
	}

	stmtSession, err := tx.Preparex(`INSERT OR REPLACE INTO sessions(host_id,user_id,source) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	for _, se := range s.Sessions {
		if _, err := stmtSession.Exec(se.HostID, se.UserID, se.Source); err != nil {
			return err
		}
	}

	stmtGPO, err := tx.Preparex(`INSERT INTO gpos(name,guid,domain,is_linked,can_edit) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET guid=excluded.guid,is_linked=excluded.is_linked,can_edit=excluded.can_edit`)
	if err != nil {
		return err
	}
	for _, g := range s.GPOs {
		if _, err := stmtGPO.Exec(g.Name, g.GUID, g.Domain, boolInt(g.IsLinked), boolInt(g.CanEdit)); err != nil {
			return err
		}
	}

	stmtADCS, err := tx.Preparex(`INSERT INTO adcs_templates(name,domain,vuln,enrollee) VALUES(?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET vuln=excluded.vuln,enrollee=excluded.enrollee`)
	if err != nil {
		return err
	}
	for _, t := range s.ADCS {
		if _, err := stmtADCS.Exec(t.Name, t.Domain, t.Vuln, t.Enrollee); err != nil {
			return err
		}
	}

	stmtPhase, err := tx.Preparex(`INSERT INTO phase_status(phase,status,skip_reason) VALUES(?,?,?) ON CONFLICT(phase) DO UPDATE SET status=excluded.status,skip_reason=excluded.skip_reason`)
	if err != nil {
		return err
	}
	for p, st := range s.Phases {
		reason := string(s.SkipReasons[p])
		if _, err := stmtPhase.Exec(string(p), int(st), reason); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`UPDATE bloodhound_meta SET collected=?,ingested=?,file_path=?,da_users=?,da_count=?,outbound_trust=? WHERE id=1`,
		boolInt(s.BH.Collected), boolInt(s.BH.Ingested), s.BH.FilePath, s.BH.DAUsers, s.BH.DACount, boolInt(s.BH.OutboundTrust)); err != nil {
		return err
	}

	// Edges: full replace inside the transaction because ApplyDelta can also
	// remove edges. Upsert alone would leak stale rows.
	if _, err := tx.Exec("DELETE FROM edges"); err != nil {
		return fmt.Errorf("save state clear edges: %w", err)
	}
	if len(s.Edges) > 0 {
		stmtEdge, err := tx.Preparex(edgeUpsertSQL)
		if err != nil {
			return fmt.Errorf("save state edges prepare: %w", err)
		}
		for _, e := range s.Edges {
			r, err := edgeToRow(e)
			if err != nil {
				return err
			}
			if _, err := stmtEdge.Exec(
				r.SourcePrincipal, r.TargetPrincipal, r.AccessRight, r.EdgeType, r.Domain, r.Source,
				r.Confidence, r.Weight, r.Exploitability, r.Noise, r.RequiresJSON, r.ValidationState,
				r.ObservedAt, r.ObservedBy, r.PreconditionsJSON, r.Provenance, r.LastVerifiedAt, r.VerificationMethod,
			); err != nil {
				return fmt.Errorf("save state edge %s→%s: %w", e.SourcePrincipal, e.TargetPrincipal, err)
			}
		}
	}

	// Tokens: full replace
	if _, err := tx.Exec("DELETE FROM tokens"); err != nil {
		return fmt.Errorf("save state clear tokens: %w", err)
	}
	stmtToken, err := tx.Preparex(`INSERT INTO tokens(type,resource,client_id,tenant,username,secret,refresh_token,scope,expires_at,source,validated) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("save state tokens prepare: %w", err)
	}
	for _, t := range s.Tokens {
		encSecret, _ := db.Encrypt(t.Secret)
		encRefresh, _ := db.Encrypt(t.RefreshToken)
		expires := ""
		if !t.ExpiresAt.IsZero() {
			expires = t.ExpiresAt.Format(time.RFC3339)
		}
		if _, err := stmtToken.Exec(t.Type, t.Resource, t.ClientID, t.Tenant, t.Username, encSecret, encRefresh, t.Scope, expires, t.Source, boolInt(t.Validated)); err != nil {
			return fmt.Errorf("save state token: %w", err)
		}
	}

	// Cloud resources: full replace
	if _, err := tx.Exec("DELETE FROM cloud_resources"); err != nil {
		return fmt.Errorf("save state clear cloud resources: %w", err)
	}
	stmtCR, err := tx.Preparex(`INSERT INTO cloud_resources(type,name,object_id,tenant,properties,discovered_by) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("save state cloud resources prepare: %w", err)
	}
	for _, r := range s.CloudResources {
		if _, err := stmtCR.Exec(r.Type, r.Name, r.ObjectID, r.Tenant, r.Properties, r.DiscoveredBy); err != nil {
			return fmt.Errorf("save state cloud resource: %w", err)
		}
	}

	return tx.Commit()
}

func (db *DB) LoadState() (*core.ADState, error) {
	s := core.NewADState()
	var err error
	s.Hosts, err = db.LoadHosts()
	if err != nil {
		return nil, err
	}
	s.Users, err = db.LoadUsers()
	if err != nil {
		return nil, err
	}
	s.Creds, err = db.LoadCreds()
	if err != nil {
		return nil, err
	}
	s.Phases, err = db.LoadPhases(s)
	if err != nil {
		return nil, err
	}
	s.BH, err = db.LoadBH()
	if err != nil {
		return nil, err
	}
	s.Groups, err = db.LoadGroups()
	if err != nil {
		return nil, err
	}
	s.Computers, err = db.LoadComputers()
	if err != nil {
		return nil, err
	}
	s.Sessions, err = db.LoadSessions()
	if err != nil {
		return nil, err
	}
	s.GPOs, err = db.LoadGPOs()
	if err != nil {
		return nil, err
	}
	s.ADCS, err = db.LoadADCSTemplates()
	if err != nil {
		return nil, err
	}
	s.Edges, err = db.LoadEdges()
	if err != nil {
		return nil, err
	}
	s.Tokens, err = db.LoadTokens()
	if err != nil {
		return nil, err
	}
	s.CloudResources, err = db.LoadCloudResources()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (db *DB) LoadEngagementJSON() (string, error) {
	s, err := db.LoadState()
	if err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return string(b), nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (db *DB) ResetPhase(p core.Phase) error {
	_, err := db.Exec(`INSERT INTO phase_status(phase,status,skip_reason) VALUES(?,0,'') ON CONFLICT(phase) DO UPDATE SET status=0,skip_reason=''`, string(p))
	return err
}

func (db *DB) SetPhaseComplete(p core.Phase) error {
	_, err := db.Exec(`INSERT INTO phase_status(phase,status) VALUES(?,2) ON CONFLICT(phase) DO UPDATE SET status=2`, string(p))
	return err
}

func (db *DB) SaveSession(s core.Session) error {
	_, err := db.Exec(`INSERT OR REPLACE INTO sessions(host_id,user_id,source) VALUES(?,?,?)`,
		s.HostID, s.UserID, s.Source)
	return err
}
func (db *DB) SaveSessions(ss []core.Session) error {
	for _, s := range ss {
		if err := db.SaveSession(s); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) SaveComputer(c core.Computer) error {
	_, err := db.Exec(`INSERT INTO computers(name,domain,sid,operating_system,is_dc) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET sid=excluded.sid,operating_system=excluded.operating_system,is_dc=excluded.is_dc`,
		c.Name, c.Domain, c.SID, c.OperatingSystem, boolInt(c.IsDC))
	return err
}

func (db *DB) SaveGroup(g core.Group) error {
	_, err := db.Exec(`INSERT INTO groups_t(name,domain,sid,description,member_count) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET sid=excluded.sid,description=excluded.description,member_count=excluded.member_count`,
		g.Name, g.Domain, g.SID, g.Description, g.MemberCount)
	return err
}

func (db *DB) SaveGPO(g core.GPO) error {
	_, err := db.Exec(`INSERT INTO gpos(name,guid,domain,is_linked,can_edit) VALUES(?,?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET guid=excluded.guid,is_linked=excluded.is_linked,can_edit=excluded.can_edit`,
		g.Name, g.GUID, g.Domain, boolInt(g.IsLinked), boolInt(g.CanEdit))
	return err
}

func (db *DB) SaveADCSTemplate(t core.ADCSTemplate) error {
	_, err := db.Exec(`INSERT INTO adcs_templates(name,domain,vuln,enrollee) VALUES(?,?,?,?)
		ON CONFLICT(name, domain) DO UPDATE SET vuln=excluded.vuln,enrollee=excluded.enrollee`,
		t.Name, t.Domain, t.Vuln, t.Enrollee)
	return err
}

func (db *DB) SaveEvidence(e core.EvidenceEntry) error {
	_, err := db.Exec(`INSERT INTO evidence(parent_id,type,phase,source,key,value,confidence,raw_output,timestamp) VALUES(?,?,?,?,?,?,?,?,datetime('now'))`,
		e.ParentID, string(e.Type), string(e.Phase), e.Source, e.Key, e.Value, e.Confidence, e.RawOutput)
	return err
}

func (db *DB) UpdateHost(ip string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	var sets []string
	var args []interface{}
	for k, v := range updates {
		sets = append(sets, fmt.Sprintf("%s=?", k))
		args = append(args, v)
	}
	args = append(args, ip)
	_, err := db.Exec(fmt.Sprintf("UPDATE hosts SET %s WHERE ip=?", strings.Join(sets, ",")), args...)
	return err
}

func (db *DB) LoadTokens() ([]core.Token, error) {
	var rows []struct {
		ID           int    `db:"id"`
		Type         string `db:"type"`
		Resource     string `db:"resource"`
		ClientID     string `db:"client_id"`
		Tenant       string `db:"tenant"`
		Username     string `db:"username"`
		Secret       string `db:"secret"`
		RefreshToken string `db:"refresh_token"`
		Scope        string `db:"scope"`
		ExpiresAt    string `db:"expires_at"`
		Source       string `db:"source"`
		Validated    int    `db:"validated"`
	}
	if err := db.Select(&rows, "SELECT * FROM tokens"); err != nil {
		return nil, err
	}
	tokens := make([]core.Token, 0, len(rows))
	for _, r := range rows {
		sec, _ := db.Decrypt(r.Secret)
		ref, _ := db.Decrypt(r.RefreshToken)
		var expires time.Time
		if r.ExpiresAt != "" {
			expires, _ = time.Parse(time.RFC3339, r.ExpiresAt)
		}
		tokens = append(tokens, core.Token{
			Type:         r.Type,
			Resource:     r.Resource,
			ClientID:     r.ClientID,
			Tenant:       r.Tenant,
			Username:     r.Username,
			Secret:       sec,
			RefreshToken: ref,
			Scope:        r.Scope,
			ExpiresAt:    expires,
			Source:       r.Source,
			Validated:    r.Validated == 1,
		})
	}
	return tokens, nil
}

func (db *DB) LoadCloudResources() ([]core.CloudResource, error) {
	var rows []struct {
		ID           int    `db:"id"`
		Type         string `db:"type"`
		Name         string `db:"name"`
		ObjectID     string `db:"object_id"`
		Tenant       string `db:"tenant"`
		Properties   string `db:"properties"`
		DiscoveredBy string `db:"discovered_by"`
	}
	if err := db.Select(&rows, "SELECT * FROM cloud_resources"); err != nil {
		return nil, err
	}
	res := make([]core.CloudResource, 0, len(rows))
	for _, r := range rows {
		res = append(res, core.CloudResource{
			Type:         r.Type,
			Name:         r.Name,
			ObjectID:     r.ObjectID,
			Tenant:       r.Tenant,
			Properties:   r.Properties,
			DiscoveredBy: r.DiscoveredBy,
		})
	}
	return res, nil
}
