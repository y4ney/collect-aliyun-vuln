package cmd

import (
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
)

const (
	StdOutput  = "stdout"
	FileOutput = "file"

	JSONFormat = "json"
	YAMLFormat = "yaml"
)

var (
	short   bool
	output  string
	format  string
	outPath string
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "fetch aliyun vuln info",
	RunE:  runFetch,
}

func init() {
	rootCmd.AddCommand(fetchCmd)
	fetchCmd.Flags().BoolVar(
		&short,
		"short",
		false,
		"Short - only include cve id, avd id, name,type, publish time,cvss score,avd link,category and status",
	)
	fetchCmd.Flags().StringVarP(
		&output,
		"output",
		"o", FileOutput,
		"Output (stdout, file)",
	)
	fetchCmd.Flags().StringVarP(
		&format,
		"format",
		"f", JSONFormat,
		"Format (json, yaml)",
	)
	fetchCmd.Flags().StringVarP(
		&outPath,
		"out-path",
		"p",
		".",
		"Path to write vuln file to. Works only with --output=file",
	)

	utils.BindFlags(fetchCmd)
}

func runFetch(cmd *cobra.Command, _ []string) error {
	return nil
}
