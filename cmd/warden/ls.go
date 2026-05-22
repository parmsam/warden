package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List secret names and metadata (values are never shown)",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, _, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		secrets, err := s.List()
		if err != nil {
			return err
		}

		if len(secrets) == 0 {
			fmt.Println("No secrets stored. Use 'warden set KEY' to add one.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY\tDESCRIPTION\tCREATED\tLAST ACCESSED")
		for _, sec := range secrets {
			desc := sec.Description
			if desc == "" {
				desc = "-"
			}
			lastAccessed := "never"
			if sec.LastAccessedAt != nil {
				lastAccessed = sec.LastAccessedAt.Local().Format(time.DateTime)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				sec.Key,
				desc,
				sec.CreatedAt.Local().Format(time.DateTime),
				lastAccessed,
			)
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(lsCmd)
}
