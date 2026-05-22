package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var setDescription string

var setCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Store a secret (prompts for value with no echo)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]

		fmt.Fprintf(os.Stderr, "Enter value for %s: ", key)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading value: %w", err)
		}

		s, log, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		if err := s.Set(key, string(raw), setDescription); err != nil {
			return err
		}

		pid, cwd, remote := callerInfo()
		if err := log.Append("set", key, cwd, remote, pid); err != nil {
			return fmt.Errorf("writing audit entry: %w", err)
		}

		fmt.Printf("Secret %q stored.\n", key)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().StringVarP(&setDescription, "description", "d", "", "Optional description")
}
