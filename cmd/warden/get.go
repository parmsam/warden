package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Decrypt and print a secret to stdout",
	Args:  cobra.ExactArgs(1),
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
		if err := log.Append("get", key, cwd, remote, pid); err != nil {
			return fmt.Errorf("writing audit entry: %w", err)
		}

		fmt.Println(value)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}
