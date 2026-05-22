package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var injectOutput string

// placeholderRe matches __warden:KEY__ where KEY is an uppercase identifier.
var placeholderRe = regexp.MustCompile(`__warden:([A-Z][A-Z0-9_]*)__`)

var injectCmd = &cobra.Command{
	Use:   "inject <template>",
	Short: "Resolve __warden:KEY__ placeholders in a template file",
	Long: `Reads a template file, replaces every __warden:KEY__ placeholder with
the decrypted secret value, and writes to stdout (or --output FILE).
Each resolved secret is logged to the audit trail.

Example .env.template:
  OPENAI_API_KEY=__warden:OPENAI_API_KEY__
  GITHUB_TOKEN=__warden:GITHUB_TOKEN__
  DATABASE_URL=postgres://localhost/myapp

Usage:
  warden inject .env.template > .env
  warden inject .env.template --output .env`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("opening template: %w", err)
		}
		defer f.Close()

		s, log, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		pid, cwd, remote := callerInfo()
		cache := map[string]string{} // resolve each key once per run

		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := placeholderRe.ReplaceAllStringFunc(scanner.Text(), func(match string) string {
				key := placeholderRe.FindStringSubmatch(match)[1]
				if v, ok := cache[key]; ok {
					return v
				}
				v, err := s.Get(key)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warden inject: %v (leaving placeholder)\n", err)
					return match
				}
				_ = log.Append("inject", key, cwd, remote, pid)
				cache[key] = v
				return v
			})
			lines = append(lines, line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading template: %w", err)
		}

		out := os.Stdout
		if injectOutput != "" {
			out, err = os.OpenFile(injectOutput, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return fmt.Errorf("opening output file: %w", err)
			}
			defer out.Close()
		}

		_, err = fmt.Fprintln(out, strings.Join(lines, "\n"))
		return err
	},
}

func init() {
	rootCmd.AddCommand(injectCmd)
	injectCmd.Flags().StringVarP(&injectOutput, "output", "o", "", "Write output to file instead of stdout (mode 0600)")
}
