package audit_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/parmsam/warden/internal/audit"
	_ "modernc.org/sqlite"
)

// newTestLog creates an in-process audit log and returns both the Log and the
// underlying *sql.DB so tests can inspect or tamper with raw rows.
func newTestLog(t *testing.T) (*audit.Log, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  DATETIME NOT NULL,
			operation  TEXT NOT NULL,
			key        TEXT NOT NULL,
			pid        INTEGER NOT NULL DEFAULT 0,
			cwd        TEXT NOT NULL DEFAULT '',
			git_remote TEXT NOT NULL DEFAULT '',
			entry_json TEXT NOT NULL,
			hash       TEXT NOT NULL
		)`)
	if err != nil {
		t.Fatalf("creating schema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return audit.New(db), db
}

func TestAppendAndEntries(t *testing.T) {
	log, _ := newTestLog(t)

	ops := []struct {
		op, key, cwd, remote string
		pid                  int
	}{
		{"set", "API_KEY", "/home/user/proj", "", 100},
		{"get", "API_KEY", "/home/user/proj", "git@github.com:u/r.git", 101},
		{"get", "DB_URL", "/tmp", "", 102},
	}
	for _, o := range ops {
		if err := log.Append(o.op, o.key, o.cwd, o.remote, o.pid); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries, err := log.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != len(ops) {
		t.Fatalf("got %d entries, want %d", len(entries), len(ops))
	}
	// Entries() is reverse chronological; most recent first.
	if entries[0].Key != "DB_URL" {
		t.Errorf("first entry should be DB_URL (most recent), got %s", entries[0].Key)
	}
	if entries[2].Key != "API_KEY" || entries[2].Operation != "set" {
		t.Errorf("last entry should be set/API_KEY, got %s/%s", entries[2].Operation, entries[2].Key)
	}
}

func TestVerifyIntact(t *testing.T) {
	log, _ := newTestLog(t)
	for i := 0; i < 5; i++ {
		if err := log.Append("get", "KEY", "/tmp", "", i); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := log.Verify(); err != nil {
		t.Errorf("expected intact chain, got: %v", err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	log, _ := newTestLog(t)
	if err := log.Verify(); err != nil {
		t.Errorf("empty log should verify cleanly, got: %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	log, db := newTestLog(t)

	for i := 0; i < 3; i++ {
		if err := log.Append("get", "KEY", "/tmp", "", i); err != nil {
			t.Fatal(err)
		}
	}

	// Tamper with the payload of entry 2 (middle of chain).
	_, err := db.Exec(`UPDATE audit_log SET entry_json = '{"tampered":true}' WHERE id = 2`)
	if err != nil {
		t.Fatalf("tampering: %v", err)
	}

	if err := log.Verify(); err == nil {
		t.Error("expected verification to fail after tampering, but it passed")
	}
}

func TestVerifySingleEntry(t *testing.T) {
	log, _ := newTestLog(t)
	if err := log.Append("set", "X", "/tmp", "", 1); err != nil {
		t.Fatal(err)
	}
	if err := log.Verify(); err != nil {
		t.Errorf("single-entry chain should verify, got: %v", err)
	}
}
