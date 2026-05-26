package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sqlx.DB
	Path       string
	encryptKey []byte
}

// getOrCreateEncryptionKey returns a persistent 32-byte encryption key stored
// alongside the database. The key is randomly generated on first use and stored
// with restrictive permissions (0600). This ensures keys survive restarts and
// are not derived from user-controllable inputs.
func getOrCreateEncryptionKey(dbPath string) ([]byte, error) {
	keyPath := dbPath + ".key"

	// Try to read existing key
	if data, err := os.ReadFile(keyPath); err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("invalid encryption key size at %s: got %d bytes, expected 32 bytes (do not regenerate - restore from backup or investigate)", keyPath, len(data))
		}
		return data, nil
	}

	// Generate new random key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}

	// Write key with restrictive permissions atomically (O_EXCL ensures first writer wins)
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			// Another process created the key concurrently, re-read it
			data, readErr := os.ReadFile(keyPath)
			if readErr != nil {
				return nil, fmt.Errorf("read concurrent key: %w", readErr)
			}
			if len(data) != 32 {
				return nil, fmt.Errorf("concurrent key at %s has invalid size: got %d bytes, expected 32", keyPath, len(data))
			}
			return data, nil
		}
		return nil, fmt.Errorf("create encryption key file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(key); err != nil {
		return nil, fmt.Errorf("write encryption key: %w", err)
	}

	log.Printf("Generated new encryption key at %s", keyPath)
	return key, nil
}

// Encrypt encrypts plaintext using AES-GCM with a versioned prefix
func (db *DB) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(db.encryptKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return "v1:" + encoded, nil
}

// Decrypt decrypts ciphertext using AES-GCM, handling versioned and legacy formats
func (db *DB) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	// Check for versioned format
	if strings.HasPrefix(ciphertext, "v1:") {
		encoded := strings.TrimPrefix(ciphertext, "v1:")
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("decrypt v1: base64 decode failed: %w", err)
		}

		block, err := aes.NewCipher(db.encryptKey)
		if err != nil {
			return "", fmt.Errorf("decrypt v1: cipher init failed: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("decrypt v1: GCM init failed: %w", err)
		}

		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return "", fmt.Errorf("decrypt v1: ciphertext too short")
		}

		nonce, cipherData := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
		if err != nil {
			return "", fmt.Errorf("decrypt v1: decryption failed: %w", err)
		}

		return string(plaintext), nil
	}

	// Legacy plaintext or old encrypted format - attempt base64 decode
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		// Not base64, assume legacy plaintext
		return ciphertext, nil
	}

	block, err := aes.NewCipher(db.encryptKey)
	if err != nil {
		return ciphertext, nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext, nil
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		// Too short, assume legacy plaintext
		return ciphertext, nil
	}

	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		// Decryption failed, assume legacy plaintext
		return ciphertext, nil
	}

	return string(plaintext), nil
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	// Create DB file with restrictive permissions if it doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create db file: %w", err)
		}
		if f != nil {
			f.Close()
		}
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

	// Ensure file permissions are restrictive (in case file already existed)
	if err := os.Chmod(path, 0600); err != nil {
		log.Printf("Warning: Could not set DB permissions: %v", err)
	}

	// Get or create encryption key
	encryptKey, err := getOrCreateEncryptionKey(path)
	if err != nil {
		return nil, fmt.Errorf("encryption key: %w", err)
	}

	dbWrapper := &DB{
		DB:         db,
		Path:       path,
		encryptKey: encryptKey,
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return dbWrapper, nil
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
	CREATE TABLE IF NOT EXISTS edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_principal TEXT NOT NULL,
		target_principal TEXT NOT NULL,
		access_right TEXT NOT NULL DEFAULT '',
		edge_type TEXT NOT NULL DEFAULT '',
		domain TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		confidence REAL NOT NULL DEFAULT 0,
		weight REAL NOT NULL DEFAULT 0,
		exploitability REAL NOT NULL DEFAULT 0,
		noise REAL NOT NULL DEFAULT 0,
		requires_json TEXT NOT NULL DEFAULT '[]',
		validation_state TEXT NOT NULL DEFAULT 'inferred',
		observed_at TEXT NOT NULL DEFAULT '',
		observed_by TEXT NOT NULL DEFAULT '',
		preconditions_json TEXT NOT NULL DEFAULT '[]',
		provenance TEXT NOT NULL DEFAULT '',
		last_verified_at TEXT NOT NULL DEFAULT '',
		verification_method TEXT NOT NULL DEFAULT ''
	);
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
		CREATE UNIQUE INDEX IF NOT EXISTS idx_computers_unique ON computers(name, domain);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_unique ON groups_t(name, domain);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_gpos_unique ON gpos(name, domain);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_adcs_unique ON adcs_templates(name, domain);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_priv_edges_unique ON edges(source_principal, target_principal, access_right, edge_type, domain);
		CREATE INDEX IF NOT EXISTS idx_priv_edges_source ON edges(source_principal);
		CREATE INDEX IF NOT EXISTS idx_priv_edges_target ON edges(target_principal);
		CREATE INDEX IF NOT EXISTS idx_priv_edges_provenance ON edges(provenance);
	`)

	for _, m := range []string{
		`ALTER TABLE execution_nodes ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE execution_nodes ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE execution_nodes ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'))`,
		`ALTER TABLE users ADD COLUMN no_preauth INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN spns TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN source_tool TEXT DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN target_account TEXT DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN confidence REAL DEFAULT 0.0`,
		`ALTER TABLE phase_status ADD COLUMN skip_reason TEXT NOT NULL DEFAULT ''`,
	} {
		db.Exec(m) // best-effort for existing DBs
	}

	if err != nil {
		return fmt.Errorf("indexes: %w", err)
	}
	log.Println("DB migrated")
	return nil
}
