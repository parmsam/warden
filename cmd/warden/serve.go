package main

import (
	"fmt"
	"os"

	"github.com/parmsam/warden/internal/daemon"
	"github.com/parmsam/warden/internal/lease"
	mcpserver "github.com/parmsam/warden/internal/mcp"
	"github.com/spf13/cobra"
)

var serveMCP bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the warden daemon on a Unix socket",
	Long: `Starts an HTTP server on ~/.warden/warden.sock that agents and
orchestrators can use to obtain leases and retrieve secrets.

With --mcp, the daemon runs in a background goroutine while an MCP stdio
server serves the foreground — useful when Claude Code spawns the process.

Daemon API:
  GET  /v1/ping
  GET  /v1/secrets
  GET  /v1/secrets/{key}      (requires X-Warden-Lease header)
  POST /v1/leases             (body: {key, ttl_seconds, cwd, git_remote, pid})
  DELETE /v1/leases/{id}
  GET  /v1/leases[?all=1]
  GET  /v1/audit`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, l, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		mgr := lease.New(s.DB())
		d := daemon.New(s, l, mgr)
		sockPath := daemon.SocketPath()

		if serveMCP {
			// Daemon runs in background; MCP stdio owns the foreground.
			go func() {
				fmt.Fprintf(os.Stderr, "warden daemon listening on %s\n", sockPath)
				if err := d.Serve(sockPath); err != nil {
					fmt.Fprintf(os.Stderr, "warden daemon: %v\n", err)
				}
			}()
			return mcpserver.Serve(s, l, mgr)
		}

		fmt.Fprintf(os.Stderr, "warden daemon listening on %s\n", sockPath)
		return d.Serve(sockPath)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().BoolVar(&serveMCP, "mcp", false, "Also start MCP stdio server (foreground)")
}
