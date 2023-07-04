package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/config"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the collect-aliyun-vuln version",
	Long:  `All software has versions. This is collect-aliyun-vuln's`,
	RunE:  runPrintVersion,
}

func runPrintVersion(cmd *cobra.Command, _ []string) error {
	fmt.Fprintf(out, "%s version %s\n", config.AppName, config.AppVersion)
	fmt.Fprintf(out, "build date: %s\n", config.BuildTime)
	fmt.Fprintf(out, "commit: %s\n\n", config.LastCommitHash)
	fmt.Fprintln(out, "https://github.com/y4ney/collect-aliyun-vuln")

	return nil
}
