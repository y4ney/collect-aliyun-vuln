package cmd

import (
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
)

const (
	NameQuery = "name"
	Id        = "id"
)

var query string
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "search aliyun vuln",
	RunE:  runSearchVuln,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVarP(&query, "query", "q", Id, "query vuln by name or id")
	utils.BindFlags(searchCmd)
}

func runSearchVuln(cmd *cobra.Command, _ []string) error {
	return nil
}
