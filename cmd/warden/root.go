package main

import (
	"os"
	"os/exec"
	"strings"

	"github.com/parmsam/warden/internal/audit"
	"github.com/parmsam/warden/internal/store"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "warden",
	Short: "Local-first secrets vault for AI coding agents",
	Long: `warden stores secrets encrypted at rest and issues short-lived leases
with a tamper-evident audit log. Run 'warden init' to get started.`,
}

// openVault is a shared helper for commands that need the store and audit log.
func openVault() (*store.Store, *audit.Log, error) {
	s, err := store.FromKeychain(store.DefaultPath())
	if err != nil {
		return nil, nil, err
	}
	return s, audit.New(s.DB()), nil
}

// callerInfo returns the current process PID, working directory, and git remote.
func callerInfo() (pid int, cwd, gitRemote string) {
	pid = os.Getpid()
	cwd, _ = os.Getwd()
	gitRemote = detectGitRemote(cwd)
	return
}

func detectGitRemote(cwd string) string {
	out, err := exec.Command("git", "-C", cwd, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
