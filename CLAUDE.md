# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
go build ./cmd/warden   # build the CLI binary
go test ./...           # run all tests
```

No lint config yet. Standard `gofmt` applies.

## Dependency rule

**Ask before adding any dependency not already in `go.mod`.** This is a hard constraint from the project owner. The current dep list (age, cobra, go-keyring, modernc.org/sqlite, golang.org/x/term) was explicitly approved; everything else needs approval first.

## Code conventions

- **No global state.** Pass `*store.Store` and `*audit.Log` explicitly to every function that needs them. The `openVault()` helper in `cmd/warden/root.go` is the only place they're constructed.
- **Error wrapping.** Always use `fmt.Errorf("context: %w", err)`. Never discard errors silently.
- **Tests.** Table-driven, using `t.TempDir()` for any DB files. Store tests use `store.Open(path, identity)` with a freshly generated identity — never the keychain.

## Package map

| Package | Status | Role |
|---|---|---|
| `internal/store` | implemented | SQLite schema, age encryption/decryption, secret CRUD |
| `internal/audit` | implemented | hash-chained append-only log, `Verify()` |
| `internal/lease` | phase 1 | records lease rows; TTL **not** enforced yet |
| `internal/daemon` | phase 2 stub | Unix socket server (empty) |
| `internal/mcp` | phase 2 stub | MCP server (empty) |
| `internal/tui` | phase 3 stub | Bubble Tea TUI (empty) |

Phase 2 work is additive — don't modify the phase 1 packages except to fix bugs.

## Audit log integrity

The hash chain is `hash_n = sha256(hash_{n-1} || entry_json_n)` with `hash_0` chaining from `""`. The `entry_json` column is the canonical payload; individual columns are for querying only. Don't change the `payload` struct field names in `internal/audit/audit.go` — that would silently break `Verify()` on existing logs.
