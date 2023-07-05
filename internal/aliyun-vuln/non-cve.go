package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
	"strconv"
)

var statusSelector = []string{
	"button.btn.btn-outline-warning.btn-sm",
	"button.btn.btn-outline-primary.btn-sm",
	"button.btn.btn-outline-danger.btn-sm",
}

type NonCveCollector struct {
	c   *colly.Collector
	url *url.URL
}

func NewNonCveCollector(scheme string, domain string, path string) *NonCveCollector {
	var collector NonCveCollector
	collector.c = colly.NewCollector()
	collector.url = utils.URL(scheme, domain, path)
	return &collector
}

func (c *NonCveCollector) GetPage(_ string) (*Page, error) {
	page, err := getPage(c.url.String(), c.c)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (c *NonCveCollector) GetMetadata() (*model.MetaData, error) {
	page, err := c.GetPage("")
	if err != nil {
		return nil, xerrors.Errorf("failed to get non cve page:%w", err)
	}

	return &model.MetaData{LastUpdate: now, NonCveVuln: page.Record}, nil
}

func (c *NonCveCollector) GetVulnList(_ string, page int) ([]*model.VulnList, error) {
	var vulns []*model.VulnList
	c.c.OnHTML("table.table", func(e *colly.HTMLElement) {
		e.ForEach("tr", func(index int, row *colly.HTMLElement) {
			avdVuln := row.ChildTexts("td")
			if avdVuln == nil {
				return
			}
			vuln := model.VulnList{
				AvdId:       avdVuln[0],
				Name:        utils.TrimNull(avdVuln[1]),
				PublishTime: avdVuln[3],
			}

			vuln.AvdLink, _ = utils.ParseLink(*c.url, row.ChildAttr("a", "href"))

			if utils.TrimNull(avdVuln[2]) == "" {
				vuln.Type = nil
			} else {
				vuln.Type = &model.VulnType{
					CweId: avdVuln[2],
					Value: row.ChildAttr("button.btn.btn-outline-secondary.btn-sm", "title"),
				}
			}

			for _, s := range statusSelector {
				status := row.ChildAttr(s, "title")
				if status != "" {
					vuln.Status = status
					break
				}
			}

			vulns = append(vulns, &vuln)
		})
	})

	c.url = utils.AddQuery(c.url, map[string]string{QueryPage: strconv.Itoa(page)})
	err := c.c.Visit(c.url.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", c.url.String(), err)
	}

	return vulns, nil
}
