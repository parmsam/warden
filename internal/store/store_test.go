package store_test

import (
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/parmsam/warden/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"), identity)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSetAndGet(t *testing.T) {
	tests := []struct {
		name, key, value, description string
	}{
		{"simple", "API_KEY", "secret123", "My API key"},
		{"empty description", "TOKEN", "tok_abc", ""},
		{"special chars", "PASS", `p@$$w0rd!"#`, "special"},
		{"unicode value", "SECRET", "日本語テスト", "unicode"},
	}

	s := newTestStore(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Set(tc.key, tc.value, tc.description); err != nil {
				t.Fatalf("Set: %v", err)
			}
			got, err := s.Get(tc.key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got != tc.value {
				t.Errorf("got %q, want %q", got, tc.value)
			}
		})
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get("NONEXISTENT"); err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestSetOverwrite(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("KEY", "original", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("KEY", "updated", ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got != "updated" {
		t.Errorf("got %q, want %q", got, "updated")
	}
}

func TestListOrder(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []string{"ZEBRA", "APPLE", "MANGO"} {
		if err := s.Set(k, "val", ""); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 3 {
		t.Fatalf("got %d secrets, want 3", len(secrets))
	}
	want := []string{"APPLE", "MANGO", "ZEBRA"}
	for i, sec := range secrets {
		if sec.Key != want[i] {
			t.Errorf("index %d: got %q, want %q", i, sec.Key, want[i])
		}
	}
}

func TestListEmpty(t *testing.T) {
	s := newTestStore(t)
	secrets, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected empty list, got %d secrets", len(secrets))
	}
}

func TestLastAccessedUpdated(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("K", "v", ""); err != nil {
		t.Fatal(err)
	}

	before, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if before[0].LastAccessedAt != nil {
		t.Error("last_accessed_at should be nil before first get")
	}

	if _, err := s.Get("K"); err != nil {
		t.Fatal(err)
	}

	after, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if after[0].LastAccessedAt == nil {
		t.Error("last_accessed_at should be set after get")
	}
}
