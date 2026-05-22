// Package lease records and enforces time-bounded access leases for secrets.
// Phase 2: TTL and revocation are enforced by the daemon. CLI commands have direct access.
package lease

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Manager records and queries lease rows in the leases table.
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
	RevokedAt *time.Time
	PID       int
	CWD       string
	GitRemote string
}

// IsActive returns true if the lease is neither expired nor revoked.
func (l *Lease) IsActive() bool {
	return l.RevokedAt == nil && time.Now().Before(l.ExpiresAt)
}

// Create records a new lease and returns it.
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

// Revoke marks the lease whose ID starts with prefix as revoked.
// prefix must be at least 4 characters. Errors if zero or multiple leases match,
// or if the matching lease is already revoked.
func (m *Manager) Revoke(prefix string) error {
	if len(prefix) < 4 {
		return fmt.Errorf("prefix too short; use at least 4 characters")
	}
	res, err := m.db.Exec(
		`UPDATE leases SET revoked_at = ? WHERE id LIKE ? AND revoked_at IS NULL`,
		time.Now().UTC(), prefix+"%")
	if err != nil {
		return fmt.Errorf("revoking lease: %w", err)
	}
	n, _ := res.RowsAffected()
	switch n {
	case 0:
		return fmt.Errorf("no active lease matches prefix %q", prefix)
	case 1:
		return nil
	default:
		return fmt.Errorf("prefix %q matched %d leases; be more specific", prefix, n)
	}
}

// GetByPrefix returns the single lease whose ID starts with prefix.
// Errors if zero or multiple leases match.
func (m *Manager) GetByPrefix(prefix string) (*Lease, error) {
	rows, err := m.db.Query(`
		SELECT id, key, created_at, expires_at, revoked_at, pid, cwd, git_remote
		FROM leases WHERE id LIKE ?`, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("querying lease: %w", err)
	}
	defer rows.Close()

	var matches []Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		matches = append(matches, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no lease found with prefix %q", prefix)
	case 1:
		return &matches[0], nil
	default:
		return nil, fmt.Errorf("prefix %q is ambiguous (%d matches); be more specific", prefix, len(matches))
	}
}

// List returns all leases, newest first.
func (m *Manager) List() ([]Lease, error) {
	rows, err := m.db.Query(`
		SELECT id, key, created_at, expires_at, revoked_at, pid, cwd, git_remote
		FROM leases ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing leases: %w", err)
	}
	defer rows.Close()
	return collectLeases(rows)
}

// ListActive returns leases that are neither expired nor revoked, ordered by expiry.
func (m *Manager) ListActive() ([]Lease, error) {
	rows, err := m.db.Query(`
		SELECT id, key, created_at, expires_at, revoked_at, pid, cwd, git_remote
		FROM leases
		WHERE revoked_at IS NULL AND expires_at > ?
		ORDER BY expires_at ASC`, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("listing active leases: %w", err)
	}
	defer rows.Close()
	return collectLeases(rows)
}

func collectLeases(rows *sql.Rows) ([]Lease, error) {
	var out []Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func scanLease(rows *sql.Rows) (Lease, error) {
	var l Lease
	var revoked sql.NullTime
	err := rows.Scan(&l.ID, &l.Key, &l.CreatedAt, &l.ExpiresAt, &revoked, &l.PID, &l.CWD, &l.GitRemote)
	if err != nil {
		return Lease{}, fmt.Errorf("scanning lease: %w", err)
	}
	if revoked.Valid {
		l.RevokedAt = &revoked.Time
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
