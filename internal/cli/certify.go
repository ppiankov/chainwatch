package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/certify"
)

var (
	certifyProfile  string
	certifySuite    string
	certifyPolicy   string
	certifyDenylist string
	certifyFormat   string
)

func init() {
	rootCmd.AddCommand(certifyCmd)
	certifyCmd.Flags().StringVar(&certifyProfile, "profile", "", "Profile to certify (required)")
	certifyCmd.Flags().StringVar(&certifySuite, "suite", "enterprise", "Certification suite (minimal|enterprise)")
	certifyCmd.Flags().StringVar(&certifyPolicy, "policy", "", "Path to policy YAML (optional)")
	certifyCmd.Flags().StringVar(&certifyDenylist, "denylist", "", "Path to denylist YAML (optional)")
	certifyCmd.Flags().StringVarP(&certifyFormat, "format", "f", "text", "Output format (text|json)")
	certifyCmd.MarkFlagRequired("profile")
}

var certifyCmd = &cobra.Command{
	Use:   "certify",
	Short: "Verify a profile passes a safety certification suite",
	Long: "Runs a curated set of safety scenarios against a profile and reports\n" +
		"pass/fail per category. Exit code 0 if all cases pass, 1 if any fail.\n\n" +
		"Available suites: " + fmt.Sprintf("%v", certify.ListSuites()),
	RunE: runCertify,
}

var runCertify = func(cmd *cobra.Command, args []string) error {
	suite, err := certify.LoadSuite(certifySuite)
	if err != nil {
		return err
	}

	result, err := certify.Run(suite, certifyProfile, certifyPolicy, certifyDenylist)
	if err != nil {
		return err
	}

	switch certifyFormat {
	case "json":
		out, err := certify.FormatJSON(result)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(certify.FormatText(result))
	}

	if result.Failed > 0 {
		os.Exit(1)
	}

	return nil
}
