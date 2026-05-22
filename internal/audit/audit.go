package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Log provides append-only, hash-chained audit logging backed by an existing *sql.DB.
// The audit_log table must already exist (created by store.Open / store.Init).
type Log struct {
	db *sql.DB
}

// New wraps an existing database connection. It does not create the schema.
func New(db *sql.DB) *Log {
	return &Log{db: db}
}

// payload is the canonical JSON shape that participates in the hash chain.
// Changing field names here breaks verification of existing logs.
type payload struct {
	Timestamp time.Time `json:"timestamp"`
	Operation string    `json:"operation"`
	Key       string    `json:"key"`
	PID       int       `json:"pid"`
	CWD       string    `json:"cwd"`
	GitRemote string    `json:"git_remote,omitempty"`
}

// Entry is a decoded audit log row returned by Entries.
type Entry struct {
	ID        int64
	Timestamp time.Time
	Operation string
	Key       string
	PID       int
	CWD       string
	GitRemote string
	Hash      string
}

// Append writes a new audit entry, chaining it to the previous hash.
// hash_n = sha256(hash_{n-1} || entry_json_n); hash_0 chains from "".
func (l *Log) Append(operation, key, cwd, gitRemote string, pid int) error {
	p := payload{
		Timestamp: time.Now().UTC(),
		Operation: operation,
		Key:       key,
		PID:       pid,
		CWD:       cwd,
		GitRemote: gitRemote,
	}
	entryJSON, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling audit entry: %w", err)
	}

	var prevHash string
	err = l.db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("reading previous hash: %w", err)
	}

	hash := chainHash(prevHash, entryJSON)

	_, err = l.db.Exec(`
		INSERT INTO audit_log (timestamp, operation, key, pid, cwd, git_remote, entry_json, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Timestamp, operation, key, pid, cwd, gitRemote, string(entryJSON), hash)
	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

// Entries returns all audit entries in reverse chronological order.
func (l *Log) Entries() ([]Entry, error) {
	rows, err := l.db.Query(`
		SELECT id, timestamp, operation, key, pid, cwd, git_remote, hash
		FROM audit_log ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Operation, &e.Key, &e.PID, &e.CWD, &e.GitRemote, &e.Hash); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Verify walks the log in ascending ID order and recomputes every hash.
// Returns nil if the chain is intact, or an error identifying the first broken entry.
func (l *Log) Verify() error {
	rows, err := l.db.Query(`SELECT id, entry_json, hash FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var id int64
		var entryJSON, stored string
		if err := rows.Scan(&id, &entryJSON, &stored); err != nil {
			return fmt.Errorf("scanning entry: %w", err)
		}
		computed := chainHash(prevHash, []byte(entryJSON))
		if computed != stored {
			return fmt.Errorf("hash mismatch at entry %d: stored=%s computed=%s", id, stored, computed)
		}
		prevHash = stored
	}
	return rows.Err()
}

func chainHash(prevHash string, entryJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(entryJSON)
	return hex.EncodeToString(h.Sum(nil))
}
