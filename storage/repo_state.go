package storage

import (
	"adpack/core"
	"encoding/json"
	"fmt"
	"strings"
)

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
	_, err := db.Exec(`INSERT INTO credentials(type,username,domain,secret,hash,target,validated,source) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(type, username, domain, target) DO UPDATE SET secret=excluded.secret,hash=excluded.hash,validated=excluded.validated,source=excluded.source`,
		c.Type, c.Username, c.Domain, c.Secret, c.Hash, c.Target, boolInt(c.Validated), c.Source)
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
	return cc, err
}

func (db *DB) SavePhases(m map[core.Phase]core.PhaseStatus) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for p, s := range m {
		_, err := tx.Exec(`INSERT INTO phase_status(phase,status) VALUES(?,?) ON CONFLICT(phase) DO UPDATE SET status=excluded.status`, string(p), int(s))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (db *DB) LoadPhases() (map[core.Phase]core.PhaseStatus, error) {
	type row struct {
		Phase  string `db:"phase"`
		Status int    `db:"status"`
	}
	var rows []row
	err := db.Select(&rows, "SELECT * FROM phase_status")
	if err != nil {
		return nil, err
	}
	m := make(map[core.Phase]core.PhaseStatus)
	for _, r := range rows {
		m[core.Phase(r.Phase)] = core.PhaseStatus(r.Status)
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

	stmtCred, err := tx.Preparex(`INSERT INTO credentials(type,username,domain,secret,hash,target,validated,source) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(type, username, domain, target) DO UPDATE SET secret=excluded.secret,hash=excluded.hash,validated=excluded.validated,source=excluded.source`)
	if err != nil {
		return err
	}
	for _, c := range s.Creds {
		if _, err := stmtCred.Exec(c.Type, c.Username, c.Domain, c.Secret, c.Hash, c.Target, boolInt(c.Validated), c.Source); err != nil {
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

	stmtPhase, err := tx.Preparex(`INSERT INTO phase_status(phase,status) VALUES(?,?) ON CONFLICT(phase) DO UPDATE SET status=excluded.status`)
	if err != nil {
		return err
	}
	for p, st := range s.Phases {
		if _, err := stmtPhase.Exec(string(p), int(st)); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`UPDATE bloodhound_meta SET collected=?,ingested=?,file_path=?,da_users=?,da_count=?,outbound_trust=? WHERE id=1`,
		boolInt(s.BH.Collected), boolInt(s.BH.Ingested), s.BH.FilePath, s.BH.DAUsers, s.BH.DACount, boolInt(s.BH.OutboundTrust)); err != nil {
		return err
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
	s.Phases, err = db.LoadPhases()
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
	_, err := db.Exec(`INSERT INTO phase_status(phase,status) VALUES(?,0) ON CONFLICT(phase) DO UPDATE SET status=0`, string(p))
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
