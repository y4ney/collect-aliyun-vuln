package cmd

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"

	"github.com/invopop/jsonschema"
)

const (
	VulnListSchema   = "vuln-list"
	VulnDetailSchema = "vuln-detail"
	MetaDataSchema   = "metadate"
)

var Type string

// schemaCmd represents the schema command
var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print the aliyun vuln's json file schema",
	RunE:  runGenerateSchema,
}

func init() {
	schemaCmd.Flags().StringVarP(
		&Type,
		"type",
		"t",
		VulnDetailSchema,
		"specify the model(only support vuln-detail vuln-list and metadate)",
	)

	utils.BindFlags(schemaCmd)
}

func runGenerateSchema(cmd *cobra.Command, _ []string) error {
	var schema *jsonschema.Schema
	switch Type {
	case VulnDetailSchema:
		schema = jsonschema.Reflect(&model.VulnDetail{})

	case VulnListSchema:
		schema = jsonschema.Reflect(&model.VulnList{})

	case MetaDataSchema:
		schema = jsonschema.Reflect(&model.MetaData{})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(schema)
}
