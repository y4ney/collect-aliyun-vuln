package cmd

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"

	"github.com/invopop/jsonschema"
)

// schemaCmd represents the schema command
var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print the aliyun vuln's json file schema",
	RunE:  runGenerateSchema,
}

func runGenerateSchema(cmd *cobra.Command, _ []string) error {
	schema := jsonschema.Reflect(&model.VulnDetail{})
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(schema)
}
