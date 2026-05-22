// Package daemon runs an HTTP server over a Unix socket, providing low-latency
// access to the vault for agents and orchestrators. Secrets are only returned
// to callers that present a valid, non-expired, non-revoked lease.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/parmsam/warden/internal/audit"
	"github.com/parmsam/warden/internal/lease"
	"github.com/parmsam/warden/internal/store"
)

const socketName = "warden.sock"

// SocketPath returns the default Unix socket path (~/.warden/warden.sock).
func SocketPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".warden", socketName)
}

// Daemon serves vault operations over a Unix socket HTTP API.
type Daemon struct {
	store  *store.Store
	audit  *audit.Log
	lease  *lease.Manager
	server *http.Server
}

// New wires up the HTTP routes and returns a ready Daemon.
func New(s *store.Store, l *audit.Log, mgr *lease.Manager) *Daemon {
	d := &Daemon{store: s, audit: l, lease: mgr}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", d.handlePing)
	mux.HandleFunc("GET /v1/secrets", d.handleList)
	mux.HandleFunc("GET /v1/secrets/{key}", d.handleGet)
	mux.HandleFunc("POST /v1/leases", d.handleCreateLease)
	mux.HandleFunc("DELETE /v1/leases/{id}", d.handleRevokeLease)
	mux.HandleFunc("GET /v1/leases", d.handleListLeases)
	mux.HandleFunc("GET /v1/audit", d.handleAudit)
	d.server = &http.Server{Handler: mux}
	return d
}

// Serve starts the HTTP server on a Unix socket at socketPath and blocks.
// Any existing socket file is removed first. Socket permissions are set to 0600.
func (d *Daemon) Serve(socketPath string) error {
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing old socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}
	go d.sweepExpiredLeases()
	return d.server.Serve(ln)
}

// Shutdown gracefully stops the server.
func (d *Daemon) Shutdown(ctx context.Context) error {
	return d.server.Shutdown(ctx)
}

// sweepExpiredLeases runs every minute to log expiry events.
// Phase 3 will add webhook callbacks here.
func (d *Daemon) sweepExpiredLeases() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Enforcement is per-request (handleGet validates TTL on each call).
		// This loop is the hook point for future notification/callback logic.
	}
}

// --- helpers -----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func callerFromHeaders(r *http.Request) (pid int, cwd, remote string) {
	pid, _ = strconv.Atoi(r.Header.Get("X-Warden-PID"))
	cwd = r.Header.Get("X-Warden-CWD")
	remote = r.Header.Get("X-Warden-Remote")
	return
}

// --- handlers ----------------------------------------------------------------

func (d *Daemon) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (d *Daemon) handleList(w http.ResponseWriter, r *http.Request) {
	secrets, err := d.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		Key         string     `json:"key"`
		Description string     `json:"description"`
		CreatedAt   time.Time  `json:"created_at"`
		LastAccess  *time.Time `json:"last_accessed_at,omitempty"`
	}
	out := make([]item, len(secrets))
	for i, s := range secrets {
		out[i] = item{s.Key, s.Description, s.CreatedAt, s.LastAccessedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGet returns the secret value only if the caller presents a valid lease.
// Agents obtain a lease via POST /v1/leases before calling this endpoint.
func (d *Daemon) handleGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	leasePrefix := r.Header.Get("X-Warden-Lease")
	if leasePrefix == "" {
		writeError(w, http.StatusUnauthorized, "X-Warden-Lease header required; obtain a lease via POST /v1/leases")
		return
	}

	l, err := d.lease.GetByPrefix(leasePrefix)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid lease: "+err.Error())
		return
	}
	if l.Key != key {
		writeError(w, http.StatusForbidden, fmt.Sprintf("lease covers %q, not %q", l.Key, key))
		return
	}
	if l.RevokedAt != nil {
		writeError(w, http.StatusForbidden, "lease has been revoked")
		return
	}
	if time.Now().After(l.ExpiresAt) {
		writeError(w, http.StatusForbidden, "lease has expired")
		return
	}

	value, err := d.store.Get(key)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	pid, cwd, remote := callerFromHeaders(r)
	_ = d.audit.Append("daemon:get", key, cwd, remote, pid)

	writeJSON(w, http.StatusOK, map[string]string{"value": value})
}

func (d *Daemon) handleCreateLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key        string `json:"key"`
		TTLSeconds int    `json:"ttl_seconds"`
		CWD        string `json:"cwd"`
		GitRemote  string `json:"git_remote"`
		PID        int    `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	// Verify the secret exists before issuing a lease for it.
	if _, err := d.store.Get(req.Key); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	l, err := d.lease.Create(req.Key, req.CWD, req.GitRemote, req.PID, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = d.audit.Append("daemon:lease", req.Key, req.CWD, req.GitRemote, req.PID)

	writeJSON(w, http.StatusCreated, l)
}

func (d *Daemon) handleRevokeLease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := d.lease.Revoke(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	pid, cwd, remote := callerFromHeaders(r)
	_ = d.audit.Append("daemon:revoke", id, cwd, remote, pid)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (d *Daemon) handleListLeases(w http.ResponseWriter, r *http.Request) {
	var (
		leases []lease.Lease
		err    error
	)
	if r.URL.Query().Get("all") == "1" {
		leases, err = d.lease.List()
	} else {
		leases, err = d.lease.ListActive()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, leases)
}

func (d *Daemon) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := d.audit.Entries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
