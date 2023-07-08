package cmd

import (
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	aliyun_vuln "github.com/y4ney/collect-aliyun-vuln/internal/aliyun-vuln"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"path/filepath"
	"strings"
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
	types   string
)

// fetchCmd represents the fetch command
var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "fetch aliyun vuln info",
	RunE:  runFetch,
}

func init() {
	rootCmd.AddCommand(fetchCmd)

	fetchCmd.Flags().StringVarP(&types, "types", "t", aliyun_vuln.CveType, fmt.Sprintf("Types(cve, non-cve),If there are multiple values, it is separated by a quiet comma"))
	fetchCmd.Flags().BoolVar(&short, "short", true, "Short - only include cve id, avd id, name,type, publish time,cvss score,avd link,category and status")
	// TODO stdout
	fetchCmd.Flags().StringVarP(&output, "output", "o", FileOutput, "Output (stdout, file)")
	// TODO yaml
	fetchCmd.Flags().StringVarP(&format, "format", "f", JSONFormat, "Format (json, yaml)")
	fetchCmd.Flags().StringVarP(&outPath, "out-path", "p", ".", "Path to write vuln file to. Works only with --output=file")

	utils.BindFlags(fetchCmd)
}

func runFetch(cmd *cobra.Command, _ []string) error {
	fetchTypes := strings.Split(types, ",")
	for _, fetchType := range fetchTypes {
		if fetchType != aliyun_vuln.CveType && fetchType != aliyun_vuln.NonCveType && fetchType != aliyun_vuln.AliyunType {
			err := xerrors.New("please specify correct types with --types")
			log.Fatal().Str("types", types).Msg(err.Error())
			return err
		}
		c := aliyun_vuln.NewAliyunVuln(types)
		if err := fetchVuln(fetchType, c); err != nil {
			return err
		}
	}
	return nil
}
func fetchVuln(fetchType string, c aliyun_vuln.AliyunVuln) error {
	// 获取页码信息
	pages, err := c.GetPage()
	if err != nil {
		err = xerrors.Errorf("failed to get page:%w", err)
		log.Error().Msg(err.Error())
		return err
	}
	log.Debug().Interface("pages", pages).Msg("success to get pages")

	for category, page := range pages {
		var bar *pb.ProgressBar
		if !verbose {
			log.Info().Str("type", fetchType).Str("category", category).Msg("start to fetch... ...")
			bar = pb.StartNew(page.Record)
		}
		for i := page.Current; i <= page.Total; i++ {
			// 获取漏洞列表
			vulns, err := c.GetVulnList(category, i)
			if err != nil {
				err = xerrors.Errorf("failed to get vuln list:%w", err)
				log.Error().Str("category", category).Int("page", i).Msgf(err.Error())
				return err
			}
			log.Debug().Str("category", category).Int("page", i).Msg("success to get vuln list")

			for _, vuln := range vulns {
				if short {
					// 输出简短的信息
					if err = Output(fetchType, vuln.AvdId, vuln); err != nil {
						return err
					}
				} else {
					// 获取漏洞信息,再输出详细信息
					vulnDetail, err := aliyun_vuln.GetVulnDetail(vuln.AvdId)
					if err != nil {
						log.Fatal().Str("AVD ID", vuln.AvdId).Msgf("failed to get vuln detail:%v", err)
					}
					log.Debug().Str("AVD ID", vuln.AvdId).Msg("success to get vuln detail")
					if err = Output(fetchType, vulnDetail.AvdId, vulnDetail); err != nil {
						return err
					}
				}
				if !verbose {
					bar.Increment()
				}
			}
		}
		if !verbose {
			bar.Increment()
		}
	}
	return nil
}

func Output(fetchType string, AvdId string, data any) error {
	if output == FileOutput {
		if err := writeVuln(fetchType, AvdId, data); err != nil {
			return err
		}
	}
	return nil
}

func writeVuln(fetchType string, AvdId string, data any) error {
	// 创建目录
	dir := filepath.Join(outPath, aliyun_vuln.AliyunType, fetchType, strings.Split(AvdId, "-")[1])
	if err := utils.Mkdir(dir); err != nil {
		err = xerrors.Errorf("failed to mkdir:%w", err)
		log.Error().Str("directory", dir).Msg(err.Error())
		return err
	}
	log.Debug().Str("directory", dir).Msg("success to mkdir")

	// 写入文件
	var filename string
	if format == JSONFormat {
		filename = fmt.Sprintf("%s.json", AvdId)
	}
	if format == YAMLFormat {
		filename = fmt.Sprintf("%s.yaml", AvdId)
	}
	if err := utils.WriteFile(filepath.Join(dir, filename), data); err != nil {
		err = xerrors.Errorf("failed to write file:%w", err)
		log.Error().Str("filename", filename).Msg(err.Error())
		return err
	}
	log.Debug().Str("filename", filename).Msg("success to write file")
	return nil
}
