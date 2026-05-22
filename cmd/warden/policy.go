package main

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	policyAgent string
	policyRepo  string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage per-agent access policies",
	Long: `Policies restrict which agents or repo paths can access a secret via
the daemon or MCP server. If no policies exist for a key, access is open.

CLI commands (warden get, warden lease) always bypass policy checks —
policies only apply to daemon and MCP access paths.

  warden policy add GITHUB_TOKEN --agent claude --repo /Users/sam/work
  warden policy ls
  warden policy rm 3`,
}

var policyAddCmd = &cobra.Command{
	Use:   "add KEY",
	Short: "Add an access policy for a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if policyAgent == "" && policyRepo == "" {
			return fmt.Errorf("specify at least one of --agent or --repo")
		}
		s, _, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		if err := s.AddPolicy(args[0], policyAgent, policyRepo); err != nil {
			return err
		}
		agent := policyAgent
		if agent == "" {
			agent = "*"
		}
		repo := policyRepo
		if repo == "" {
			repo = "*"
		}
		fmt.Printf("Policy added for %q: agent=%s repo=%s\n", args[0], agent, repo)
		return nil
	},
}

var policyRmCmd = &cobra.Command{
	Use:   "rm ID",
	Short: "Remove a policy by its numeric ID (shown in 'warden policy ls')",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid policy ID %q: must be a number", args[0])
		}
		s, _, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.RemovePolicy(id); err != nil {
			return err
		}
		fmt.Printf("Policy %d removed.\n", id)
		return nil
	},
}

var policyLsCmd = &cobra.Command{
	Use:   "ls [KEY]",
	Short: "List all policies, or policies for a specific secret",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var key string
		if len(args) == 1 {
			key = args[0]
		}

		s, _, err := openVault()
		if err != nil {
			return err
		}
		defer s.Close()

		policies, err := s.ListPolicies(key)
		if err != nil {
			return err
		}
		if len(policies) == 0 {
			if key != "" {
				fmt.Printf("No policies for %q. Access is open.\n", key)
			} else {
				fmt.Println("No policies configured. All secrets are open-access.")
			}
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tKEY\tAGENT\tREPO PATH\tCREATED")
		for _, p := range policies {
			agent := p.AgentName
			if agent == "" {
				agent = "*"
			}
			repo := p.RepoPath
			if repo == "" {
				repo = "*"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
				p.ID, p.Key, agent, repo,
				p.CreatedAt.Local().Format(time.DateTime))
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyAddCmd, policyRmCmd, policyLsCmd)
	policyAddCmd.Flags().StringVar(&policyAgent, "agent", "", "Agent name to allow (e.g. claude, cursor; empty = any)")
	policyAddCmd.Flags().StringVar(&policyRepo, "repo", "", "Repo path prefix to allow (e.g. /Users/sam/prod; empty = any)")
}
