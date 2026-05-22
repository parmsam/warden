// Package mcp exposes warden as an MCP server over stdio.
// Claude Code configuration:
//
//	{ "mcpServers": { "warden": { "command": "warden", "args": ["mcp"] } } }
package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/parmsam/warden/internal/audit"
	"github.com/parmsam/warden/internal/lease"
	"github.com/parmsam/warden/internal/store"
)

// Serve starts the MCP stdio server and blocks until stdin is closed.
// Each warden_get call auto-creates a 5-minute lease so the access is
// traceable and revocable via `warden lease revoke`.
func Serve(s *store.Store, l *audit.Log, mgr *lease.Manager) error {
	srv := server.NewMCPServer("warden", "0.2.0")

	srv.AddTool(mcplib.NewTool("warden_get",
		mcplib.WithDescription(`Retrieve a secret from the local warden vault.

The value is decrypted in memory and returned only to this session.
Every call is logged to a tamper-evident audit trail (PID, working
directory, git remote) and a 5-minute lease is automatically recorded.
Use warden_list to discover available secret names.`),
		mcplib.WithString("key",
			mcplib.Required(),
			mcplib.Description("Secret name (e.g. OPENAI_API_KEY, GITHUB_TOKEN)"),
		),
	), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		key, err := req.RequireString("key")
		if err != nil {
			return nil, err
		}

		value, err := s.Get(key)
		if err != nil {
			return nil, err
		}

		cwd, _ := os.Getwd()
		pid := os.Getpid()

		if _, err := mgr.Create(key, cwd, "", pid, 5*time.Minute); err != nil {
			// Lease failure is non-fatal; the value is still returned.
			fmt.Fprintf(os.Stderr, "warden: lease create: %v\n", err)
		}
		_ = l.Append("mcp:get", key, cwd, "", pid)

		return mcplib.NewToolResultText(value), nil
	})

	srv.AddTool(mcplib.NewTool("warden_list",
		mcplib.WithDescription("List all secret names stored in the warden vault. Values are never returned."),
	), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		secrets, err := s.List()
		if err != nil {
			return nil, err
		}
		names := make([]string, len(secrets))
		for i, sec := range secrets {
			desc := sec.Key
			if sec.Description != "" {
				desc = fmt.Sprintf("%s — %s", sec.Key, sec.Description)
			}
			names[i] = desc
		}
		if len(names) == 0 {
			return mcplib.NewToolResultText("No secrets stored. Run 'warden set KEY' to add one."), nil
		}
		return mcplib.NewToolResultText(strings.Join(names, "\n")), nil
	})

	return server.ServeStdio(srv)
}
