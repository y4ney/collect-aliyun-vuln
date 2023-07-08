package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
)

var statusSelector = []string{
	"button.btn.btn-outline-warning.btn-sm",
	"button.btn.btn-outline-primary.btn-sm",
	"button.btn.btn-outline-danger.btn-sm",
	"button.btn.btn-outline-info.btn-sm",
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

func (c *NonCveCollector) GetPage() (map[string]*Page, error) {
	Pages := make(map[string]*Page, 1)
	page, err := getPage(c.url.String(), c.c)
	if err != nil {
		return nil, err
	}
	Pages[NonCveType] = page
	return Pages, nil
}

func (c *NonCveCollector) GetMetadata() (*model.MetaData, error) {
	pages, err := c.GetPage()
	if err != nil {
		return nil, xerrors.Errorf("failed to get non cve page:%w", err)
	}
	return &model.MetaData{LastUpdate: now, NonCveVuln: pages[NonCveType].Record}, nil
}

func (c *NonCveCollector) GetVulnList(_ string, page int) ([]*model.VulnList, error) {
	vulns, err := getVulnListBySearch("", page)
	if err != nil {
		return nil, err
	}

	return vulns, nil
}
