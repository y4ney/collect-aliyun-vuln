package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
	"regexp"
	"strconv"
)

const (
	Scheme          = "https"
	Domain          = "avd.aliyun.com"
	CvdVulnListPath = "nvd/list"
)

type Page struct {
	Current int
	Total   int
	Record  int
}

type Collector struct {
	c   *colly.Collector
	url *url.URL
}

func NewPage(text string) (*Page, error) {
	// 使用正则提取text中的数字
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(text, -1)

	// 类型转换
	currentPage, err := strconv.Atoi(matches[0])
	if err != nil {
		return nil, xerrors.Errorf("failed to convert current page %s:%w", matches[0], err)
	}
	totalPage, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, xerrors.Errorf("failed to convert total page %s:%w", matches[1], err)
	}
	records, err := strconv.Atoi(matches[2])
	if err != nil {
		return nil, xerrors.Errorf("failed to convert records %s:%w", matches[2], err)
	}

	return &Page{Current: currentPage, Total: totalPage, Record: records}, nil
}

func NewCollector(scheme string, domain string, path string) *Collector {
	var collector Collector
	collector.c = colly.NewCollector()
	collector.url = utils.URL(scheme, domain, path)
	return &collector
}

func (c *Collector) SetCollector(parallel int) {
	c.c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: parallel})
}

func (c *Collector) getPage(selector string) (*Page, error) {
	// 获取文本
	var text string
	c.c.OnHTML(selector, func(e *colly.HTMLElement) {
		text = e.Text
	})
	if err := c.c.Visit(c.url.String()); err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", c.url.String(), err)
	}
	if text == "" {
		return nil, xerrors.New("text is null")
	}

	// 获取页码

	page, err := NewPage(text)
	if err != nil {
		return nil, xerrors.Errorf("failed to get page:%w", err)
	}

	return page, nil
}
