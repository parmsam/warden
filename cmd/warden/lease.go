package main

import (
	"fmt"
	"time"

	"github.com/parmsam/warden/internal/lease"
	"github.com/spf13/cobra"
)

var leaseTTL time.Duration

var leaseCmd = &cobra.Command{
	Use:   "lease KEY",
	Short: "Fetch a secret and record a time-bounded lease",
	Long: `Decrypts the secret and writes it to stdout, then records a lease row
with an expiry time. Expiry enforcement is phase 2; this establishes the record.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]

		s, log, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		value, err := s.Get(key)
		if err != nil {
			return err
		}

		pid, cwd, remote := callerInfo()

		mgr := lease.New(s.DB())
		l, err := mgr.Create(key, cwd, remote, pid, leaseTTL)
		if err != nil {
			return fmt.Errorf("creating lease: %w", err)
		}

		if err := log.Append("lease", key, cwd, remote, pid); err != nil {
			return fmt.Errorf("writing audit entry: %w", err)
		}

		// Secret goes to stdout; lease metadata to stderr so agents can
		// capture the value cleanly while still seeing the lease ID.
		fmt.Println(value)
		fmt.Fprintf(cmd.ErrOrStderr(), "lease %s expires %s\n",
			l.ID[:8], l.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(leaseCmd)
	leaseCmd.Flags().DurationVar(&leaseTTL, "ttl", 5*time.Minute, "Lease duration (e.g. 30s, 5m, 1h)")
}
