package main

import (
	"github.com/parmsam/warden/internal/lease"
	"github.com/parmsam/warden/internal/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive terminal UI",
	Long:  "Browse secrets, audit history, and leases in a full-screen terminal UI.\n\nKeys: ↑↓/jk navigate  Tab/1-3 switch tab  q quit",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, l, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		secrets, err := s.List()
		if err != nil {
			return err
		}
		entries, err := l.Entries()
		if err != nil {
			return err
		}
		mgr := lease.New(s.DB())
		leases, err := mgr.List()
		if err != nil {
			return err
		}

		return tui.Run(secrets, entries, leases)
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
