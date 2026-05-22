// Package lease records time-bounded access leases for secrets.
// Phase 1: leases are written and readable but expiry is not enforced.
// Phase 2 will add enforcement (revocation, background expiry sweep).
package lease

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Manager records lease rows in the leases table.
// The table must already exist (created by store.Open / store.Init).
type Manager struct {
	db *sql.DB
}

// New creates a Manager backed by an existing *sql.DB.
func New(db *sql.DB) *Manager {
	return &Manager{db: db}
}

// Lease is a time-bounded access record for a secret.
type Lease struct {
	ID        string
	Key       string
	CreatedAt time.Time
	ExpiresAt time.Time
	PID       int
	CWD       string
	GitRemote string
}

// Create records a new lease and returns it.
// Expiry is stored but not enforced in phase 1.
func (m *Manager) Create(key, cwd, gitRemote string, pid int, ttl time.Duration) (*Lease, error) {
	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("generating lease ID: %w", err)
	}
	now := time.Now().UTC()
	l := &Lease{
		ID:        id,
		Key:       key,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		PID:       pid,
		CWD:       cwd,
		GitRemote: gitRemote,
	}
	_, err = m.db.Exec(`
		INSERT INTO leases (id, key, created_at, expires_at, pid, cwd, git_remote)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Key, l.CreatedAt, l.ExpiresAt, l.PID, l.CWD, l.GitRemote)
	if err != nil {
		return nil, fmt.Errorf("recording lease for %q: %w", key, err)
	}
	return l, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
