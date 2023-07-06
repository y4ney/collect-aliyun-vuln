package cmd

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"

	"github.com/invopop/jsonschema"
)

// schemaCmd represents the schema command
var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print the aliyun vuln's json file schema",
	RunE:  runGenerateSchema,
}
var Type string

func init() {
	schemaCmd.Flags().StringVarP(
		&Type,
		"type",
		"t",
		"vuln-detail",
		"specify the model(only support vuln-detail vuln-list and metadate)",
	)

	utils.BindFlags(schemaCmd)
}
func runGenerateSchema(cmd *cobra.Command, _ []string) error {
	var schema *jsonschema.Schema
	switch Type {
	case "vuln-detail":
		schema = jsonschema.Reflect(&model.VulnDetail{})

	case "vuln-list":
		schema = jsonschema.Reflect(&model.VulnList{})

	case "metadate":
		schema = jsonschema.Reflect(&model.MetaData{})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(schema)
}
