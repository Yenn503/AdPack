package storage

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
	"github.com/jmoiron/sqlx"
)

type DB struct {
	*sqlx.DB
	Path string
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sqlx.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{DB: db, Path: path}, nil
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./adpack.db"
	}
	return filepath.Join(home, ".adpack", "state.db")
}

func migrate(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL UNIQUE,
		hostname TEXT DEFAULT '',
		domain TEXT DEFAULT '',
		os TEXT DEFAULT '',
		is_dc INTEGER DEFAULT 0,
		ports_open TEXT DEFAULT '',
		discovery_src TEXT DEFAULT '',
		edr TEXT DEFAULT '',
		evasion_hist TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		domain TEXT DEFAULT '',
		sam_account_name TEXT DEFAULT '',
		sid TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		is_admin INTEGER DEFAULT 0,
		is_da INTEGER DEFAULT 0,
		description TEXT DEFAULT '',
		source TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS groups_t (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		domain TEXT DEFAULT '',
		sid TEXT DEFAULT '',
		description TEXT DEFAULT '',
		member_count INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS computers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		domain TEXT DEFAULT '',
		sid TEXT DEFAULT '',
		operating_system TEXT DEFAULT '',
		is_dc INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		source TEXT DEFAULT '',
		FOREIGN KEY(host_id) REFERENCES hosts(id),
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		username TEXT NOT NULL,
		domain TEXT DEFAULT '',
		secret TEXT DEFAULT '',
		hash TEXT DEFAULT '',
		target TEXT DEFAULT '',
		validated INTEGER DEFAULT 0,
		source TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS evidence (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		parent_id INTEGER DEFAULT 0,
		type TEXT NOT NULL,
		phase TEXT NOT NULL,
		source TEXT DEFAULT '',
		key TEXT DEFAULT '',
		value TEXT DEFAULT '',
		confidence REAL DEFAULT 1.0,
		raw_output TEXT DEFAULT '',
		timestamp TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS phase_status (
		phase TEXT PRIMARY KEY,
		status INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS gpos (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		guid TEXT DEFAULT '',
		domain TEXT DEFAULT '',
		is_linked INTEGER DEFAULT 0,
		can_edit INTEGER DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS adcs_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		domain TEXT DEFAULT '',
		vuln TEXT DEFAULT '',
		enrollee TEXT DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		campaign_id TEXT NOT NULL DEFAULT '',
		trace_id TEXT NOT NULL DEFAULT '',
		parent_id TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL,
		class INTEGER NOT NULL DEFAULT 0,
		source TEXT NOT NULL DEFAULT '',
		payload TEXT NOT NULL DEFAULT '{}',
		timestamp TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS execution_nodes (
		id TEXT PRIMARY KEY,
		campaign_id TEXT NOT NULL DEFAULT '',
		parent_id TEXT NOT NULL DEFAULT '',
		tool TEXT NOT NULL DEFAULT '',
		phase TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		input TEXT NOT NULL DEFAULT '{}',
		output TEXT NOT NULL DEFAULT '{}',
		attempt INTEGER NOT NULL DEFAULT 0,
		last_error TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		started_at TEXT NOT NULL DEFAULT (datetime('now')),
		finished_at TEXT
	);
	CREATE TABLE IF NOT EXISTS execution_edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		parent_id TEXT NOT NULL,
		child_id TEXT NOT NULL,
		FOREIGN KEY(parent_id) REFERENCES execution_nodes(id),
		FOREIGN KEY(child_id) REFERENCES execution_nodes(id)
	);
	CREATE TABLE IF NOT EXISTS bloodhound_meta (
		id INTEGER PRIMARY KEY CHECK(id=1),
		collected INTEGER DEFAULT 0,
		ingested INTEGER DEFAULT 0,
		file_path TEXT DEFAULT '',
		da_users TEXT DEFAULT '',
		da_count INTEGER DEFAULT 0,
		outbound_trust INTEGER DEFAULT 0
	);
	INSERT OR IGNORE INTO bloodhound_meta(id,collected,ingested) VALUES(1,0,0);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("schema exec: %w", err)
	}
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_sessions_host ON sessions(host_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(type);
		CREATE INDEX IF NOT EXISTS idx_evidence_phase ON evidence(phase);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_unique ON users(username, domain);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_creds_unique ON credentials(type, username, domain, target);
		CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
		CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_nodes_campaign ON execution_nodes(campaign_id);
		CREATE INDEX IF NOT EXISTS idx_nodes_status ON execution_nodes(status);
		CREATE INDEX IF NOT EXISTS idx_edges_parent ON execution_edges(parent_id);
		CREATE INDEX IF NOT EXISTS idx_edges_child ON execution_edges(child_id);
	`)

	for _, m := range []string{
		`ALTER TABLE execution_nodes ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE execution_nodes ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE execution_nodes ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'))`,
		`ALTER TABLE users ADD COLUMN no_preauth INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN spns TEXT NOT NULL DEFAULT ''`,
	} {
		db.Exec(m) // best-effort for existing DBs
	}

	if err != nil {
		return fmt.Errorf("indexes: %w", err)
	}
	log.Println("DB migrated")
	return nil
}
