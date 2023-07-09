package cmd

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	aliyun_vuln "github.com/y4ney/collect-aliyun-vuln/internal/aliyun-vuln"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
)

const (
	QueryName = "name"
	QueryID   = "id"
)

var (
	query string
	value string
)
var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search aliyun vuln",
	RunE:  runSearchVuln,
}

func init() {
	rootCmd.AddCommand(searchCmd)
	searchCmd.Flags().StringVarP(&query, "query", "q", QueryName, "query by (name , id)")
	searchCmd.Flags().StringVarP(&value, "value", "", "", "query value")
	utils.BindFlags(searchCmd)
}

func runSearchVuln(_ *cobra.Command, _ []string) error {
	var vulns []*model.VulnList
	switch query {
	case QueryID:
		vuln, err := aliyun_vuln.SearchForId(value)
		if err != nil {
			err = xerrors.Errorf("failed to search %w", err)
			log.Error().Str("Vuln ID", query).Msg(err.Error())
			return err
		}
		if vuln.Type == nil {
			vuln.Type = &model.VulnType{}
		}
		vulns = append(vulns, &model.VulnList{
			CveId:       vuln.CveId,
			AvdId:       vuln.AvdId,
			Name:        vuln.Name,
			Type:        vuln.Type,
			PublishTime: vuln.PublishTime,
			CvssScore:   vuln.CvssScore,
			AvdLink:     vuln.AvdLink,
			Category:    vuln.Category,
			Status:      vuln.Status,
		})
	case QueryName:
		var err error
		vulns, err = aliyun_vuln.SearchVulnListByName(value)
		if err != nil {
			err = xerrors.Errorf("failed to search %w", err)
			log.Error().Str("Vuln Name", query).Msg(err.Error())
			return err
		}
	default:
		return fmt.Errorf("query %q is not supported", format)
	}
	printTable(vulns)

	return nil
}

func printTable(vulns []*model.VulnList) {
	var data [][]string
	for _, vuln := range vulns {
		if vuln.Type == nil {
			vuln.Type = &model.VulnType{}
		}
		data = append(data, []string{vuln.AvdId, vuln.CveId, vuln.Name, vuln.Type.Value, vuln.Status, vuln.AvdLink})
	}
	table := tablewriter.NewWriter(out)
	table.SetHeader([]string{"AVD ID", "CVE ID", "Vuln Name", "Vuln Type", "Vuln Status", "Link"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data) // Add Bulk Data
	table.Render()
}
