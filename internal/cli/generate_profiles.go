package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/macprofile"
)

var (
	generateAppArmorProfile  string
	generateAppArmorOutput   string
	generateAppArmorDenylist string
	generateAppArmorName     string

	generateSELinuxProfile  string
	generateSELinuxOutput   string
	generateSELinuxDenylist string
	generateSELinuxModule   string
)

func init() {
	rootCmd.AddCommand(generateAppArmorCmd)
	rootCmd.AddCommand(generateSELinuxCmd)

	generateAppArmorCmd.Flags().StringVar(&generateAppArmorProfile, "profile", "", "Safety profile name to translate")
	generateAppArmorCmd.Flags().StringVarP(&generateAppArmorOutput, "output", "o", "", "Output file path for generated AppArmor profile")
	generateAppArmorCmd.Flags().StringVar(&generateAppArmorDenylist, "denylist", "", "Path to denylist YAML (default: ~/.chainwatch/denylist.yaml)")
	generateAppArmorCmd.Flags().StringVar(&generateAppArmorName, "name", "", "AppArmor profile name (default: chainwatch-<profile>)")
	_ = generateAppArmorCmd.MarkFlagRequired("profile")
	_ = generateAppArmorCmd.MarkFlagRequired("output")

	generateSELinuxCmd.Flags().StringVar(&generateSELinuxProfile, "profile", "", "Safety profile name to translate")
	generateSELinuxCmd.Flags().StringVarP(&generateSELinuxOutput, "output", "o", "", "Output file path for generated SELinux .te module")
	generateSELinuxCmd.Flags().StringVar(&generateSELinuxDenylist, "denylist", "", "Path to denylist YAML (default: ~/.chainwatch/denylist.yaml)")
	generateSELinuxCmd.Flags().StringVar(&generateSELinuxModule, "module", "", "SELinux module name (default: chainwatch_<profile>)")
	_ = generateSELinuxCmd.MarkFlagRequired("profile")
	_ = generateSELinuxCmd.MarkFlagRequired("output")
}

var generateAppArmorCmd = &cobra.Command{
	Use:   "generate-apparmor",
	Short: "Generate an AppArmor profile from chainwatch policy boundaries",
	Long:  "Translates effective denylist restrictions (default denylist + selected profile boundaries) to AppArmor syntax.",
	RunE:  runGenerateAppArmor,
}

var generateSELinuxCmd = &cobra.Command{
	Use:   "generate-selinux",
	Short: "Generate a SELinux type-enforcement module from chainwatch policy boundaries",
	Long:  "Translates effective denylist restrictions (default denylist + selected profile boundaries) to SELinux .te policy.",
	RunE:  runGenerateSELinux,
}

func runGenerateAppArmor(cmd *cobra.Command, args []string) error {
	restrictions, err := macprofile.LoadRestrictions(generateAppArmorProfile, generateAppArmorDenylist)
	if err != nil {
		return fmt.Errorf("load restrictions: %w", err)
	}

	profileName := strings.TrimSpace(generateAppArmorName)
	if profileName == "" {
		profileName = "chainwatch-" + strings.ReplaceAll(generateAppArmorProfile, "_", "-")
	}

	content, err := macprofile.GenerateAppArmor(profileName, restrictions)
	if err != nil {
		return fmt.Errorf("generate AppArmor profile: %w", err)
	}

	if err := writeGeneratedProfile(generateAppArmorOutput, content); err != nil {
		return err
	}

	fmt.Printf("Generated AppArmor profile: %s\n", generateAppArmorOutput)
	fmt.Println("Load or replace on Linux:")
	fmt.Printf("  sudo apparmor_parser -r %s\n", generateAppArmorOutput)
	return nil
}

func runGenerateSELinux(cmd *cobra.Command, args []string) error {
	restrictions, err := macprofile.LoadRestrictions(generateSELinuxProfile, generateSELinuxDenylist)
	if err != nil {
		return fmt.Errorf("load restrictions: %w", err)
	}

	moduleName := strings.TrimSpace(generateSELinuxModule)
	if moduleName == "" {
		moduleName = "chainwatch_" + strings.ReplaceAll(generateSELinuxProfile, "-", "_")
	}

	content, err := macprofile.GenerateSELinux(moduleName, restrictions)
	if err != nil {
		return fmt.Errorf("generate SELinux module: %w", err)
	}

	if err := writeGeneratedProfile(generateSELinuxOutput, content); err != nil {
		return err
	}

	base := strings.TrimSuffix(generateSELinuxOutput, filepath.Ext(generateSELinuxOutput))
	modPath := base + ".mod"
	ppPath := base + ".pp"

	fmt.Printf("Generated SELinux type enforcement file: %s\n", generateSELinuxOutput)
	fmt.Println("Compile and load on Linux:")
	fmt.Printf("  checkmodule -M -m -o %s %s\n", modPath, generateSELinuxOutput)
	fmt.Printf("  semodule_package -o %s -m %s\n", ppPath, modPath)
	fmt.Printf("  sudo semodule -i %s\n", ppPath)
	return nil
}

func writeGeneratedProfile(path, content string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is required")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}

	return nil
}
