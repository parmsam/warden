# warden

A local-first secrets vault built for the age of AI coding agents.

---

## The problem

When you give Claude Code, Cursor, or Codex access to your machine, they inherit
everything in your shell environment — including every API key you've ever
exported in `~/.zshrc` or dropped into a `.env` file.

That means:

- **No accountability.** There's no record of which agent accessed which secret,
  from which project, or when.
- **No scoping.** An agent working in a throwaway sandbox has the same
  `STRIPE_LIVE_KEY` as one working in production.
- **No expiry.** Once a key leaks into a process, it's available for the
  lifetime of that session — or longer if it ends up in a log.
- **Sprawl.** The same secret gets copy-pasted into `.env` files across a dozen
  repos, each a potential leak point.

The rest of the modern agent stack — sandboxed execution, session analytics,
continuous code review — is moving toward local-first and audited. Secret
access hasn't caught up.

## What warden does

warden sits between your agents and your secrets. Instead of reading from `.env`
or shell env directly, an agent asks warden for a secret by name. Warden
decrypts it, **logs the access**, and hands it back. That's the core loop.

More specifically:

- **Encrypted at rest.** Secrets are stored in a local SQLite database,
  encrypted with [age](https://age-encryption.org) (X25519). The private key
  lives in the OS keychain (macOS Keychain, Windows Credential Manager,
  libsecret on Linux) — never on disk in plaintext.
- **Audited access.** Every `get` and `lease` call records the caller's PID,
  working directory, and git remote. You can always answer: *which agent, from
  which repo, touched which secret at what time.*
- **Short-lived leases.** Instead of handing out a raw key forever, warden
  records a lease with an expiry. Future versions enforce revocation; today the
  record is there for review.
- **Tamper-evident log.** Audit entries are hash-chained
  (`sha256(prev_hash || entry_json)`). Run `warden audit verify` to confirm
  nothing has been deleted or edited.
- **Local-first.** No cloud, no telemetry, no network calls. The vault is a
  single file at `~/.warden/warden.db`.

## How agents access secrets

There are two different situations, and they work differently:

### 1. The key that starts the agent (e.g. `ANTHROPIC_API_KEY`)

The host process needs this key *before* the agent session opens, so it has to
come from the environment. Warden handles the injection step:

```sh
# In a wrapper script — not in .zshrc, not in .env
export ANTHROPIC_API_KEY=$(warden get ANTHROPIC_API_KEY)
claude
```

The key isn't stored in any file in any repo. Every injection is logged.

### 2. Secrets the agent needs *during* its work

Once an agent is running, it may need to call GitHub, query a database, or hit
a third-party API. This is where the MCP server (phase 2) comes in.

Claude Code and other MCP-aware agents can call a `warden_get` tool directly:

```
Agent needs GITHUB_TOKEN to push a branch
  → emits tool_use { name: "warden_get", key: "GITHUB_TOKEN" }
  → Claude Code's MCP client forwards it to the warden daemon
  → warden decrypts the secret, logs the access (pid, cwd, git remote)
  → returns the value as a tool_result
  → agent uses it in the next shell command
```

The raw value still flows through the agent framework — that's unavoidable. What
warden provides is **accountability and centralization**: a single place secrets
live, a log of every access, and a foundation for TTL enforcement and per-repo
scoping.

## Install

```sh
go install github.com/parmsam/warden/cmd/warden@latest
```

## Quick start

```sh
warden init                           # generate master key, create ~/.warden/warden.db
warden set OPENAI_API_KEY -d "OpenAI" # prompt for value (no echo), store encrypted
warden set GITHUB_TOKEN
warden ls                             # list names + metadata; values never shown
warden get OPENAI_API_KEY             # decrypt to stdout, log the access
warden lease GITHUB_TOKEN --ttl 5m   # same, but record an expiring lease
warden audit                          # show full access log, newest first
warden audit verify                   # recompute hash chain, confirm integrity
```

## Technical details

| Concern | Approach |
|---|---|
| Encryption | age X25519 (filippo.io/age) |
| Key storage | OS keychain (zalando/go-keyring) |
| Database | SQLite, pure Go (modernc.org/sqlite) |
| Audit integrity | sha256 hash chain over `entry_json` |
| Transport (phase 2) | Unix socket daemon + MCP server |

## Roadmap

### Phase 2 — agent integrations

- **MCP server** (`warden serve --mcp`) — exposes a `warden_get` tool so
  Claude Code, Cursor, Codex, and any other MCP-aware agent can fetch secrets
  via tool calls without shelling out.
- **Unix socket daemon** (`warden serve`) — keeps a single decrypted-identity
  process alive so agents can make low-latency requests without spawning a new
  process and re-prompting the keychain on every call.
- **Lease enforcement** — honor the TTLs already recorded in phase 1; refuse
  `get` calls on expired leases and support `warden lease revoke <id>`.
- **Per-agent scoping** — tag a secret as accessible only to specific agent
  names (e.g. `claude`, `cursor`) or repo paths (e.g. `/Users/sam/prod/*`).
- **Dummy-value substitution** — agents load a `.env.template` with
  placeholders like `OPENAI_API_KEY=__warden:OPENAI_API_KEY__` instead of real
  keys. The MCP tool or daemon resolves placeholders at use time, so even if an
  agent logs its own environment or is compromised by prompt injection, there is
  nothing real to exfiltrate.

### Phase 3 — visibility and polish

- **TUI** (`warden tui`) — interactive terminal UI (Bubble Tea + Lip Gloss) for
  browsing secrets, active leases, and audit history without reading raw table
  output.
- **TTL expiry sweeper** — background goroutine (or launchd/systemd timer) that
  marks expired leases and optionally notifies via a configurable webhook.
- **goreleaser + Homebrew tap** — `brew install parmsam/tap/warden` and a
  signed `install.sh` for teams that don't have Go installed.

## License

MIT
