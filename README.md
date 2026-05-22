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

- **Encrypted at rest.** Secrets are stored in a local SQLite database,
  encrypted with [age](https://age-encryption.org) (X25519). The private key
  lives in the OS keychain (macOS Keychain, Windows Credential Manager,
  libsecret on Linux) — never on disk in plaintext.
- **Audited access.** Every operation records the caller's PID, working
  directory, and git remote. You can always answer: *which agent, from which
  repo, touched which secret at what time.*
- **Short-lived leases.** Agents obtain a lease with a TTL before accessing a
  secret via the daemon. Expired and revoked leases are refused. Revoke on
  demand with `warden lease revoke`.
- **Tamper-evident log.** Audit entries are hash-chained
  (`sha256(prev_hash || entry_json)`). Run `warden audit verify` to confirm
  nothing has been deleted or edited.
- **MCP integration.** Claude Code, Cursor, and Codex can call `warden_get`
  as a native tool call — no shell scripts required.
- **Local-first.** No cloud, no telemetry, no network calls. The vault is a
  single file at `~/.warden/warden.db`.

## How agents access secrets

There are two situations, and they work differently:

### 1. The key that starts the agent (e.g. `ANTHROPIC_API_KEY`)

The host process needs this key *before* the agent session opens, so it has to
come from the environment. Warden handles the injection step:

```sh
# wrapper script — not in .zshrc, not in .env
export ANTHROPIC_API_KEY=$(warden get ANTHROPIC_API_KEY)
claude
```

Or use a template file so nothing real ever sits in env at rest:

```sh
# .env.template (safe to commit)
ANTHROPIC_API_KEY=__warden:ANTHROPIC_API_KEY__

# inject resolves placeholders and writes .env (mode 0600)
warden inject .env.template --output .env
```

### 2. Secrets the agent needs *during* its work

Add warden to Claude Code's MCP config and agents can fetch secrets directly
via tool calls — no shell scripts, no env vars, fully logged:

```json
{
  "mcpServers": {
    "warden": {
      "command": "warden",
      "args": ["mcp"]
    }
  }
}
```

The flow:
```
Agent needs GITHUB_TOKEN to push a branch
  → calls warden_get("GITHUB_TOKEN")
  → warden decrypts, logs the access (pid, cwd, git remote), creates a 5-min lease
  → returns the value as a tool result
  → agent uses it in the next shell command
```

### 3. Agents that use the daemon directly

Long-running orchestrators can talk to the daemon over a Unix socket
(`~/.warden/warden.sock`) without re-prompting the keychain on every request:

```sh
warden serve &                        # start daemon in background
# POST /v1/leases → get a lease ID
# GET  /v1/secrets/{key} with X-Warden-Lease header → get value
```

The daemon enforces TTLs and revocation per-request. The CLI (`warden get`)
always grants direct human access and bypasses lease checks.

## Install

```sh
go install github.com/parmsam/warden/cmd/warden@latest
```

> If `warden` isn't found after installing, add Go's bin directory to your PATH:
> ```sh
> echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc && source ~/.zshrc
> ```

## Quick start

```sh
# One-time setup
warden init                              # generate master key, create ~/.warden/warden.db

# Managing secrets
warden set OPENAI_API_KEY -d "OpenAI"   # prompt for value (no echo), store encrypted
warden set GITHUB_TOKEN
warden ls                               # list names + metadata; values never shown

# Direct access (human / scripts)
warden get OPENAI_API_KEY               # decrypt to stdout, log the access
warden lease GITHUB_TOKEN --ttl 10m    # get value + record an expiring lease
warden inject .env.template            # resolve __warden:KEY__ placeholders

# Audit
warden audit                            # full access log, newest first
warden audit verify                     # recompute hash chain, confirm integrity

# Lease management
warden lease ls                         # active leases
warden lease ls --all                   # include expired and revoked
warden lease revoke abc123              # revoke by ID prefix

# Per-agent access policies (enforced by daemon + MCP)
warden policy add STRIPE_KEY --agent claude --repo /Users/sam/prod
warden policy ls
warden policy rm 3

# Daemon and MCP server
warden serve                            # start daemon on ~/.warden/warden.sock
warden serve --mcp                      # daemon + MCP stdio server together
warden mcp                             # MCP stdio server only (for Claude Code)

# Interactive UI
warden tui                              # browse secrets, audit log, and leases
```

## Technical details

| Concern | Approach |
|---|---|
| Encryption | age X25519 (filippo.io/age) |
| Key storage | OS keychain (zalando/go-keyring) |
| Database | SQLite, pure Go (modernc.org/sqlite) |
| Audit integrity | sha256 hash chain over `entry_json` |
| Daemon transport | HTTP over Unix socket (`~/.warden/warden.sock`) |
| Agent integration | MCP stdio server (mark3labs/mcp-go) |
| TUI | Bubble Tea + Lip Gloss |
| Releases | goreleaser + Homebrew tap |

## What's next

- **TTL expiry webhooks** — notify a configurable endpoint when leases expire,
  for orchestrators that need active notification rather than polling.
- **Homebrew tap** — `brew install parmsam/tap/warden` once the
  `parmsam/homebrew-tap` repo and `HOMEBREW_TAP_TOKEN` secret are configured.
- **Lease enforcement for per-agent scoping** — today policies are checked in
  the daemon; a future version will let the MCP server mint scoped tokens that
  can only access the keys the policy allows.

## License

MIT
