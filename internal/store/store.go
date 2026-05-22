package store

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
// The schema is applied on every open (CREATE TABLE IF NOT EXISTS is idempotent).
func Open(dbPath string, identity *age.X25519Identity) (*Store, error) {
	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	if err := applySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
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

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying *sql.DB so callers (e.g. audit, lease) can share the connection.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Secret is a metadata-only view of a stored secret (never includes the plaintext value).
type Secret struct {
	Key            string
	Description    string
	CreatedAt      time.Time
	LastAccessedAt *time.Time
}

// Set encrypts value and upserts it under key. Existing values are overwritten.
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
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("executing schema statement: %w", err)
		}
	}
	return nil
}
