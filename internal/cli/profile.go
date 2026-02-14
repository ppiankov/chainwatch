package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/profile"
)

func init() {
	rootCmd.AddCommand(profileCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCheckCmd)
	profileCmd.AddCommand(profileApplyCmd)

	// Root-level aliases
	rootCmd.AddCommand(applyProfileCmd)
	rootCmd.AddCommand(checkProfileCmd)
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage safety profiles",
	Long:  "List, check, and inspect safety profiles for AI agent enforcement.",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available safety profiles",
	RunE:  runProfileList,
}

var profileCheckCmd = &cobra.Command{
	Use:   "check <name>",
	Short: "Validate a profile loads cleanly",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileCheck,
}

var profileApplyCmd = &cobra.Command{
	Use:   "apply <name>",
	Short: "Show what patterns a profile adds",
	Long:  "Loads a profile and displays its patterns. Use --profile flag on exec/proxy to apply at runtime.",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfileApply,
}

// Root-level aliases
var applyProfileCmd = &cobra.Command{
	Use:    "apply-profile <name>",
	Short:  "Show what patterns a profile adds (alias for profile apply)",
	Args:   cobra.ExactArgs(1),
	RunE:   runProfileApply,
	Hidden: false,
}

var checkProfileCmd = &cobra.Command{
	Use:    "check-profile <name>",
	Short:  "Validate a profile loads cleanly (alias for profile check)",
	Args:   cobra.ExactArgs(1),
	RunE:   runProfileCheck,
	Hidden: false,
}

func runProfileList(cmd *cobra.Command, args []string) error {
	names := profile.List()
	if len(names) == 0 {
		fmt.Println("No profiles available.")
		return nil
	}

	fmt.Println("Available profiles:")
	for _, name := range names {
		p, err := profile.Load(name)
		if err != nil {
			fmt.Printf("  %-15s (error loading: %v)\n", name, err)
			continue
		}
		fmt.Printf("  %-15s %s\n", name, p.Description)
	}
	return nil
}

func runProfileCheck(cmd *cobra.Command, args []string) error {
	name := args[0]
	p, err := profile.Load(name)
	if err != nil {
		return fmt.Errorf("failed to load profile %q: %w", name, err)
	}

	if err := profile.Validate(p); err != nil {
		return fmt.Errorf("profile %q is invalid: %w", name, err)
	}

	fmt.Printf("Profile %q (%s) is valid.\n", name, p.Name)
	fmt.Printf("  Authority patterns:  %d\n", len(p.AuthorityBoundaries))
	fmt.Printf("  URL patterns:        %d\n", len(p.ExecutionBoundaries.URLs))
	fmt.Printf("  File patterns:       %d\n", len(p.ExecutionBoundaries.Files))
	fmt.Printf("  Command patterns:    %d\n", len(p.ExecutionBoundaries.Commands))
	if p.Policy != nil {
		fmt.Printf("  Policy rules:        %d\n", len(p.Policy.Rules))
	}
	return nil
}

func runProfileApply(cmd *cobra.Command, args []string) error {
	name := args[0]
	p, err := profile.Load(name)
	if err != nil {
		return fmt.Errorf("failed to load profile %q: %w", name, err)
	}

	fmt.Printf("Profile: %s (%s)\n", p.Name, p.Description)
	fmt.Println()

	if len(p.AuthorityBoundaries) > 0 {
		fmt.Println("Authority boundaries:")
		for _, ab := range p.AuthorityBoundaries {
			fmt.Printf("  - /%s/  →  %s\n", ab.Pattern, ab.Reason)
		}
		fmt.Println()
	}

	if len(p.ExecutionBoundaries.URLs) > 0 {
		fmt.Println("URL patterns:")
		for _, u := range p.ExecutionBoundaries.URLs {
			fmt.Printf("  - %s\n", u)
		}
		fmt.Println()
	}

	if len(p.ExecutionBoundaries.Files) > 0 {
		fmt.Println("File patterns:")
		for _, f := range p.ExecutionBoundaries.Files {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println()
	}

	if len(p.ExecutionBoundaries.Commands) > 0 {
		fmt.Println("Command patterns:")
		for _, c := range p.ExecutionBoundaries.Commands {
			fmt.Printf("  - %s\n", c)
		}
		fmt.Println()
	}

	if p.Policy != nil && len(p.Policy.Rules) > 0 {
		fmt.Println("Policy rules:")
		for _, r := range p.Policy.Rules {
			fmt.Printf("  - purpose=%s resource=%s → %s\n", r.Purpose, r.ResourcePattern, r.Decision)
		}
		fmt.Println()
	}

	fmt.Println("To apply at runtime:")
	fmt.Printf("  chainwatch exec --profile %s -- <command>\n", name)
	fmt.Printf("  chainwatch proxy --profile %s --port 8888\n", name)
	return nil
}
