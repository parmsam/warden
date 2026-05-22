package main

import (
	"fmt"

	"github.com/parmsam/warden/internal/store"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the warden vault",
	Long: `Generate a new X25519 master key, store it in the OS keychain,
and create the vault database at ~/.warden/warden.db.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := store.DefaultPath()
		if err := store.Init(path); err != nil {
			return err
		}
		fmt.Printf("Vault initialized at %s\n", path)
		fmt.Println("Master key stored in OS keychain.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
