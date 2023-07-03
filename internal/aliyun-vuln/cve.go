package aliyun_vuln

import (
	"fmt"
	"github.com/cheggaaa/pb"
	"github.com/gocolly/colly"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"log"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	QueryType       = "type"
	QueryPage       = "page"
	cveVulnListPage = "body > main > div > div > div:nth-child(2) > div > span"
	cvdVulnList     = "body > main > div > div > div.my-3.px-3.pt-2.bg-white.rounded.shadow-sm.table-responsive > table"

	OS                = "操作系统"
	Database          = "数据库"
	Application       = "应用程序"
	WebApplication    = "WEB应用"
	HardwareEquipment = "硬件设备"
)

var (
	Categories = []string{OS, Database, Application, WebApplication, HardwareEquipment}
)

func (c *Collector) GetCveVulnListPage() (map[string]*Page, error) {
	pages := make(map[string]*Page, len(Categories))
	for _, category := range Categories {
		c.url = utils.AddQuery(c.url, map[string]string{QueryType: category})
		p, err := c.getPage(cveVulnListPage)
		if err != nil {
			return nil, err
		}
		pages[category] = p
	}
	return pages, nil
}

func (c *Collector) GetCveVulnList(pages map[string]*Page) error {
	log.Println("Saving aliyun cve vuln list...")
	for _, category := range Categories {
		bar := pb.StartNew(pages[category].Total)
		for i := pages[category].Current; i < pages[category].Total; i++ {
			// 获取 CVE 漏洞列表
			vulns, err := c.getCveVulnList(category, i, cvdVulnList)
			if err != nil {
				return xerrors.Errorf("failed to get cve vuln list:%w", err)
			}

			// 创建目录，保存文件
			if err = utils.Mkdir(category); err != nil {
				return xerrors.Errorf("failed to mkdir %s:%w", category, err)
			}
			err = utils.WriteFile(filepath.Join(category, fmt.Sprintf("%s-%v.json", category, i)), vulns)
			if err != nil {
				return err
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (c *Collector) getCveVulnList(category string, page int, selector string) ([]model.VulnOverview, error) {
	var vulns []model.VulnOverview
	c.c.OnHTML(selector, func(e *colly.HTMLElement) {
		e.ForEach(selector+" > tbody > tr", func(_ int, row *colly.HTMLElement) {
			var vuln model.VulnOverview
			row.ForEachWithBreak(selector+" > tbody > tr > td", func(index int, cell *colly.HTMLElement) bool {
				switch index {
				// 获取 CVE 编号和链接
				case 0:
					vuln.Link, vuln.AvdId = parseLink(*c.url, cell.ChildAttr("a", "href"))
					vuln.CveId = strings.TrimSpace(cell.Text)

				// 获取漏洞名称
				case 1:
					name := strings.TrimSpace(cell.Text)
					if name == "N/A" {
						vuln.Name = ""
					} else {
						vuln.Name = name
					}
				// 获取 CWE 编号和其含义
				case 2:
					cweId := strings.TrimSpace(cell.Text)
					if cweId == "未定义" {
						vuln.Type = nil
					} else {
						var vulnType model.VulnType
						vulnType.Value = cell.ChildAttr("button", "title")
						vulnType.CweId = cweId
						vuln.Type = &vulnType
					}
				// 获取公布时间
				case 3:
					vuln.PublishTime = strings.TrimSpace(cell.Text)
				// 获取 CVSS 分数
				case 4:
					score := strings.TrimSpace(cell.Text)
					if score == "N/A" {
						vuln.CvssScore = 0
					} else {
						vuln.CvssScore, _ = strconv.ParseFloat(score, 64)
					}
				}
				return true
			})
			vuln.Category = category
			vulns = append(vulns, vuln)
		})
	})

	c.url = utils.AddQuery(c.url, map[string]string{QueryType: category, QueryPage: strconv.Itoa(page)})
	err := c.c.Visit(c.url.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", c.url.String(), err)
	}
	return vulns, nil
}

func parseLink(URL url.URL, text string) (string, string) {
	URL.Path = ""
	URL.RawQuery = ""
	link := URL.String() + text
	return link, strings.Split(link, "=")[1]
}
