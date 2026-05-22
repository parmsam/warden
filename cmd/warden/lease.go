package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/parmsam/warden/internal/lease"
	"github.com/spf13/cobra"
)

var leaseTTL time.Duration
var leaseShowAll bool

// leaseCmd fetches a secret and records an expiring lease.
// Subcommands: revoke, ls.
// Cobra routes to a subcommand when the first arg matches its name;
// otherwise RunE runs with the arg as the secret key.
var leaseCmd = &cobra.Command{
	Use:   "lease KEY",
	Short: "Fetch a secret and record a time-bounded lease",
	Long: `Decrypts the secret and writes it to stdout, records a lease row with
an expiry time, and logs the access. The daemon enforces TTLs on lease-gated
access; the CLI always grants direct access.

  warden lease OPENAI_API_KEY --ttl 10m
  warden lease revoke abc123
  warden lease ls`,
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

		fmt.Println(value)
		fmt.Fprintf(cmd.ErrOrStderr(), "lease %s expires %s\n",
			l.ID[:8], l.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

var leaseRevokeCmd = &cobra.Command{
	Use:   "revoke ID",
	Short: "Revoke a lease by ID prefix (min 4 chars)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, log, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		mgr := lease.New(s.DB())
		if err := mgr.Revoke(args[0]); err != nil {
			return err
		}

		pid, cwd, remote := callerInfo()
		_ = log.Append("lease:revoke", args[0], cwd, remote, pid)
		fmt.Printf("Lease %s… revoked.\n", args[0])
		return nil
	},
}

var leaseLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List leases (active only by default; --all for full history)",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, _, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		mgr := lease.New(s.DB())
		var leases []lease.Lease
		if leaseShowAll {
			leases, err = mgr.List()
		} else {
			leases, err = mgr.ListActive()
		}
		if err != nil {
			return err
		}

		if len(leases) == 0 {
			if leaseShowAll {
				fmt.Println("No leases recorded.")
			} else {
				fmt.Println("No active leases. Use --all to show expired and revoked leases.")
			}
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tKEY\tCREATED\tEXPIRES\tSTATUS")
		now := time.Now()
		for _, l := range leases {
			status := "active"
			if l.RevokedAt != nil {
				status = "revoked"
			} else if now.After(l.ExpiresAt) {
				status = "expired"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				l.ID[:8],
				l.Key,
				l.CreatedAt.Local().Format(time.DateTime),
				l.ExpiresAt.Local().Format(time.DateTime),
				status,
			)
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(leaseCmd)
	leaseCmd.AddCommand(leaseRevokeCmd, leaseLsCmd)
	leaseCmd.Flags().DurationVar(&leaseTTL, "ttl", 5*time.Minute, "Lease duration (e.g. 30s, 5m, 1h)")
	leaseLsCmd.Flags().BoolVar(&leaseShowAll, "all", false, "Show expired and revoked leases too")
}
