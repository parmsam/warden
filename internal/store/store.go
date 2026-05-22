package store

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
	_ "modernc.org/sqlite"
)

const (
	keychainService = "warden"
	keychainUser    = "master-identity"
)

// DefaultPath returns ~/.warden/warden.db.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".warden", "warden.db")
}

// Init generates a new X25519 master identity, stores the private key in the OS
// keychain, and creates the SQLite database at dbPath. Errors if already initialized.
func Init(dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return fmt.Errorf("creating warden directory: %w", err)
	}
	if _, err := os.Stat(dbPath); err == nil {
		return fmt.Errorf("vault already initialized at %s; delete it to start over", dbPath)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating master identity: %w", err)
	}
	if err := keyring.Set(keychainService, keychainUser, identity.String()); err != nil {
		return fmt.Errorf("storing master key in keychain: %w", err)
	}

	s, err := Open(dbPath, identity)
	if err != nil {
		return err
	}
	return s.Close()
}

// Open opens (or creates) the database at dbPath using the given identity.
// Schema is applied on every open (idempotent). Migrations run automatically.
func Open(dbPath string, identity *age.X25519Identity) (*Store, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	if err := applySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return &Store{db: db, identity: identity}, nil
}

// FromKeychain loads the master identity from the OS keychain and opens the store.
func FromKeychain(dbPath string) (*Store, error) {
	privKey, err := keyring.Get(keychainService, keychainUser)
	if err != nil {
		return nil, fmt.Errorf("reading master key from keychain (run 'warden init' first): %w", err)
	}
	identity, err := age.ParseX25519Identity(privKey)
	if err != nil {
		return nil, fmt.Errorf("parsing master identity: %w", err)
	}
	return Open(dbPath, identity)
}

// Store wraps the database and holds the age identity for encryption/decryption.
type Store struct {
	db       *sql.DB
	identity *age.X25519Identity
}

func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying *sql.DB so callers (audit, lease, daemon) can share the connection.
func (s *Store) DB() *sql.DB { return s.db }

// Secret is a metadata-only view of a stored secret (values are never included).
type Secret struct {
	Key            string
	Description    string
	CreatedAt      time.Time
	LastAccessedAt *time.Time
}

// Set encrypts value and upserts it under key.
func (s *Store) Set(key, value, description string) error {
	ciphertext, err := s.encrypt(value)
	if err != nil {
		return fmt.Errorf("encrypting %q: %w", key, err)
	}
	_, err = s.db.Exec(`
		INSERT INTO secrets (key, ciphertext, description, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			ciphertext  = excluded.ciphertext,
			description = excluded.description,
			created_at  = excluded.created_at`,
		key, ciphertext, description, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("storing secret %q: %w", key, err)
	}
	return nil
}

// Get decrypts and returns the value for key. Updates last_accessed_at on success.
func (s *Store) Get(key string) (string, error) {
	var ciphertext []byte
	err := s.db.QueryRow(`SELECT ciphertext FROM secrets WHERE key = ?`, key).Scan(&ciphertext)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("secret %q not found", key)
	}
	if err != nil {
		return "", fmt.Errorf("reading secret %q: %w", key, err)
	}
	value, err := s.decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypting secret %q: %w", key, err)
	}
	if _, err := s.db.Exec(`UPDATE secrets SET last_accessed_at = ? WHERE key = ?`, time.Now().UTC(), key); err != nil {
		return "", fmt.Errorf("updating last_accessed_at for %q: %w", key, err)
	}
	return value, nil
}

// List returns metadata for all secrets ordered by key. Values are never included.
func (s *Store) List() ([]Secret, error) {
	rows, err := s.db.Query(`
		SELECT key, description, created_at, last_accessed_at
		FROM secrets ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}
	defer rows.Close()

	var out []Secret
	for rows.Next() {
		var sec Secret
		var accessed sql.NullTime
		if err := rows.Scan(&sec.Key, &sec.Description, &sec.CreatedAt, &accessed); err != nil {
			return nil, fmt.Errorf("scanning secret row: %w", err)
		}
		if accessed.Valid {
			sec.LastAccessedAt = &accessed.Time
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// Policy restricts access to a secret by agent name and/or repo path prefix.
// Empty AgentName or RepoPath fields act as wildcards.
type Policy struct {
	ID        int64
	Key       string
	AgentName string
	RepoPath  string
	CreatedAt time.Time
}

// AddPolicy creates an access policy for key. Empty agentName or repoPath means "any".
func (s *Store) AddPolicy(key, agentName, repoPath string) error {
	_, err := s.db.Exec(`
		INSERT INTO secret_policies (key, agent_name, repo_path, created_at)
		VALUES (?, ?, ?, ?)`,
		key, agentName, repoPath, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("adding policy for %q: %w", key, err)
	}
	return nil
}

// RemovePolicy deletes the policy with the given ID.
func (s *Store) RemovePolicy(id int64) error {
	res, err := s.db.Exec(`DELETE FROM secret_policies WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("removing policy %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("policy %d not found", id)
	}
	return nil
}

// ListPolicies returns all policies, optionally filtered by key (empty = all).
func (s *Store) ListPolicies(key string) ([]Policy, error) {
	q := `SELECT id, key, agent_name, repo_path, created_at FROM secret_policies`
	var args []any
	if key != "" {
		q += ` WHERE key = ?`
		args = append(args, key)
	}
	q += ` ORDER BY key, id`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Key, &p.AgentName, &p.RepoPath, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CheckPolicy returns true if the caller (agentName, callerCWD) may access key.
// If no policies are set for key, access is always allowed (open by default).
// Non-empty RepoPath is matched as a prefix against callerCWD.
func (s *Store) CheckPolicy(key, agentName, callerCWD string) (bool, error) {
	policies, err := s.ListPolicies(key)
	if err != nil {
		return false, err
	}
	if len(policies) == 0 {
		return true, nil
	}
	for _, p := range policies {
		agentOK := p.AgentName == "" || p.AgentName == agentName
		repoOK := p.RepoPath == "" || strings.HasPrefix(callerCWD, p.RepoPath)
		if agentOK && repoOK {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) encrypt(plaintext string) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, s.identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalizing encryption: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *Store) decrypt(ciphertext []byte) (string, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), s.identity)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading plaintext: %w", err)
	}
	return string(plain), nil
}

func openDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// WAL mode allows concurrent reads alongside daemon writes.
	for _, pragma := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA busy_timeout=5000`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting %q: %w", pragma, err)
		}
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}
	return db, nil
}

func applySchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS secrets (
			key              TEXT PRIMARY KEY,
			ciphertext       BLOB NOT NULL,
			description      TEXT NOT NULL DEFAULT '',
			created_at       DATETIME NOT NULL,
			last_accessed_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS leases (
			id         TEXT PRIMARY KEY,
			key        TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			pid        INTEGER NOT NULL DEFAULT 0,
			cwd        TEXT NOT NULL DEFAULT '',
			git_remote TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  DATETIME NOT NULL,
			operation  TEXT NOT NULL,
			key        TEXT NOT NULL,
			pid        INTEGER NOT NULL DEFAULT 0,
			cwd        TEXT NOT NULL DEFAULT '',
			git_remote TEXT NOT NULL DEFAULT '',
			entry_json TEXT NOT NULL,
			hash       TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS secret_policies (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			key        TEXT NOT NULL,
			agent_name TEXT NOT NULL DEFAULT '',
			repo_path  TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("executing schema statement: %w", err)
		}
	}
	return nil
}

// migrate applies incremental schema changes that can't use CREATE TABLE IF NOT EXISTS.
func migrate(db *sql.DB) error {
	// Phase 2: add revoked_at to leases.
	// SQLite does not support IF NOT EXISTS for ADD COLUMN; we ignore the duplicate error.
	if _, err := db.Exec(`ALTER TABLE leases ADD COLUMN revoked_at DATETIME`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("adding revoked_at to leases: %w", err)
		}
	}
	return nil
}
