package main

import (
	"github.com/parmsam/warden/internal/lease"
	mcpserver "github.com/parmsam/warden/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start the MCP stdio server (for Claude Code / Cursor integration)",
	Long: `Starts a Model Context Protocol server on stdio that exposes:
  warden_get(key)  — decrypt and return a secret (auto-creates a 5-min lease)
  warden_list()    — list all secret names

Add to Claude Code's MCP config (~/.claude.json or project .claude/mcp.json):

  {
    "mcpServers": {
      "warden": {
        "command": "warden",
        "args": ["mcp"]
      }
    }
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, l, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()
		mgr := lease.New(s.DB())
		return mcpserver.Serve(s, l, mgr)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
