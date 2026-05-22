package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show the audit log (reverse chronological)",
	RunE:  runAuditList,
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the audit log hash chain",
	RunE:  runAuditVerify,
}

func runAuditList(cmd *cobra.Command, args []string) error {
	s, log, err := openVault()
	if err != nil {
		return err
	}
	defer s.Close()

	entries, err := log.Entries()
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("Audit log is empty.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tOP\tKEY\tPID\tCWD\tGIT REMOTE")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			e.Timestamp.Local().Format(time.RFC3339),
			e.Operation,
			e.Key,
			e.PID,
			e.CWD,
			e.GitRemote,
		)
	}
	return w.Flush()
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	s, log, err := openVault()
	if err != nil {
		return err
	}
	defer s.Close()

	if err := log.Verify(); err != nil {
		return fmt.Errorf("audit log integrity check FAILED: %w", err)
	}
	fmt.Println("Audit log integrity OK.")
	return nil
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditVerifyCmd)
}
