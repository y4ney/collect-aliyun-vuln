package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/rs/zerolog/log"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
	"strconv"
	"time"
)

const (
	QueryType = "type"
	QueryPage = "page"
	QueryId   = "id"

	OS                = "操作系统"
	Database          = "数据库"
	Application       = "应用程序"
	WebApplication    = "WEB应用"
	HardwareEquipment = "硬件设备"
)

var (
	categories = []string{OS, Database, Application, WebApplication, HardwareEquipment}
	now        = time.Now().Local()
)

type CveCollector struct {
	c   *colly.Collector
	url *url.URL
}

func NewCveCollector(scheme string, domain string, path string) *CveCollector {
	var collector CveCollector
	collector.c = colly.NewCollector()
	collector.url = utils.URL(scheme, domain, path)
	return &collector
}

func (c *CveCollector) GetPage(category string) (*Page, error) {
	c.url = utils.AddQuery(c.url, map[string]string{QueryType: category})
	page, err := getPage(c.url.String(), c.c)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (c *CveCollector) GetMetadata() (*model.MetaData, error) {
	categoryVulns := make(map[string]int, 4)
	cveVuln := 0
	for _, category := range categories {
		page, err := c.GetPage(category)
		if err != nil {
			return nil, xerrors.Errorf("failed to get %s page:%w", category, err)
		}
		categoryVulns[category] = page.Record
		cveVuln += page.Record
	}

	return &model.MetaData{LastUpdate: now, CategoryVuln: categoryVulns, CveVuln: cveVuln}, nil
}

func (c *CveCollector) GetVulnList(category string, page int) ([]*model.VulnList, error) {
	var vulns []*model.VulnList
	c.c.OnHTML("table.table", func(e *colly.HTMLElement) {
		e.ForEach("tr", func(index int, row *colly.HTMLElement) {
			cveVuln := row.ChildTexts("td")
			if cveVuln == nil {
				return
			}
			vuln := model.VulnList{
				CveId:       cveVuln[0],
				Name:        utils.TrimNull(cveVuln[1]),
				PublishTime: utils.TrimNull(cveVuln[3]),
				Category:    category,
			}

			vuln.AvdLink, vuln.AvdId = utils.ParseLink(*c.url, row.ChildAttr("a", "href"))

			if utils.TrimNull(cveVuln[2]) == "" {
				vuln.Type = nil
			} else {
				vuln.Type = &model.VulnType{
					CweId: cveVuln[2],
					Value: row.ChildAttr("button", "title"),
				}
			}

			score, err := utils.FormatScore(cveVuln[4])
			if err != nil {
				log.Fatal().Str("CVSS评分", cveVuln[4]).Msgf("failed to convert cvss score:%v", err)
				return
			}
			vuln.CvssScore = score

			vulns = append(vulns, &vuln)
		})
	})

	c.url = utils.AddQuery(c.url, map[string]string{QueryType: category, QueryPage: strconv.Itoa(page)})
	err := c.c.Visit(c.url.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", c.url.String(), err)
	}
	return vulns, nil
}
