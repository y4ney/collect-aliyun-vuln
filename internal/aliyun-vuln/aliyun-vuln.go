package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/rs/zerolog/log"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
	"regexp"
	"strconv"
)

const (
	Scheme = "https"
	Domain = "avd.aliyun.com"

	CvdVulnListPath    = "nvd/list"
	NonCvdVulnListPath = "nonvd/list"

	VulnDetailPath = "detail"
)

type AliyunVuln interface {
	// GetPage 获取页码数据
	GetPage(category string) (*Page, error)
	// GetMetadata 获取元数据
	GetMetadata() (*model.MetaData, error)
	// GetVulnList 获取漏洞列表数据
	GetVulnList(category string, page int) ([]*model.VulnList, error)
}

type Page struct {
	Current int
	Total   int
	Record  int
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

func getPage(url string, c *colly.Collector) (*Page, error) {
	// 获取文本
	var page *Page
	c.OnHTML("div.d-flex.justify-content-between.align-items-center", func(e *colly.HTMLElement) {
		var err error
		page, err = NewPage(e.Text)
		if err != nil {
			log.Fatal().Str("page", e.Text).Msgf("failed to convert to page:%v", err)
		}
	})
	if err := c.Visit(url); err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", url, err)
	}

	return page, nil
}

func GetVulnDetail(vulnId string, c colly.Collector, url *url.URL) (*model.VulnDetail, error) {
	var vuln model.VulnDetail
	// 上方
	c.OnHTML("div.px-lg-5.px-3.py-lg-3.pt-4.bg-white", func(e *colly.HTMLElement) {
		// 获取漏洞名称
		title := e.ChildTexts("h5 > span")
		vuln.Name = utils.TrimNull(title[0])

		// 获取CVE编号、利用情况、补丁情况和披露时间
		belowTitle := e.ChildTexts("div.metric-value")
		vuln.CveId = utils.TrimNull(belowTitle[0])
		vuln.ExploitState = utils.TrimNull(belowTitle[1])
		vuln.PatchState = utils.TrimNull(belowTitle[2])
		vuln.PublishTime = belowTitle[3]

		// 获取NVD链接和分类
		vuln.NvdLink = e.ChildAttr("a", "href")
		vuln.Category = utils.TrimNull(e.ChildTexts("li")[1])

	})

	// 左下方
	// 获取漏洞描述和修复建议
	c.OnHTML("div.py-4.pl-4.pr-4.px-2.bg-white.rounded.shadow-sm", func(e *colly.HTMLElement) {
		detail := e.ChildTexts("div.text-detail.pt-2.pb-4")
		vuln.Description = utils.CleanText(detail[0])
		vuln.FixSuggestion = detail[1]
	})
	// 获取参考链接
	c.OnHTML("div.text-detail.pb-3.pt-2.reference", func(e *colly.HTMLElement) {
		vuln.References = e.ChildAttrs("a", "href")
	})
	// 获取受影响软件情况
	c.OnHTML("div.pb-4.pt-3.table-responsive > table.table > tbody", func(e *colly.HTMLElement) {
		var affectSoftwares []*model.AffectSoftwareState
		e.ForEachWithBreak("tr", func(index int, row *colly.HTMLElement) bool {
			if index > 0 && index%2 == 0 {
				texts := row.ChildTexts("td.bg-light")
				affectSoftware := &model.AffectSoftwareState{
					Type:    texts[0],
					Vendor:  texts[1],
					Product: texts[2],
					Version: texts[3],
				}
				if len(texts) >= 6 {
					affectSoftware.Scope = utils.CleanText(texts[5])
				}
				affectSoftwares = append(affectSoftwares, affectSoftware)
			}
			return true
		})
		vuln.AffectStates = affectSoftwares
	})

	// 右下方
	c.OnHTML("div.cvss-breakdown", func(e *colly.HTMLElement) {
		// 获取CVSS评分
		score, err := utils.FormatScore(e.ChildText("div.cvss-breakdown__score.cvss-breakdown__score--high"))
		if err != nil {
			log.Fatal().Float64("CVSS评分/阿里云评分", score).
				Msgf("failed to convert score:%v", err)
			return
		}
		if e.ChildText("div.cvss-breakdown__heading") == "阿里云评分" {
			vuln.AvdScore = score
		} else {
			vuln.CvssScore = score
		}

		// 获取CVSS向量
		cvssDesc := e.ChildTexts("div.cvss-breakdown__desc")
		vuln.AttackPath = utils.TrimNull(cvssDesc[0])
		vuln.AttackComplex = utils.TrimNull(cvssDesc[1])
		vuln.PermissionRequire = utils.TrimNull(cvssDesc[2])
		vuln.AffectScope = utils.TrimNull(cvssDesc[3])
		if len(cvssDesc) == 8 {
			vuln.UserInteraction = utils.TrimNull(cvssDesc[4])
			vuln.Availability = utils.TrimNull(cvssDesc[5])
			vuln.Confidentiality = utils.TrimNull(cvssDesc[6])
			vuln.Integrity = utils.TrimNull(cvssDesc[7])
		}
		if len(cvssDesc) == 10 {
			vuln.ExpMaturity = utils.TrimNull(cvssDesc[4])
			vuln.PatchState = utils.TrimNull(cvssDesc[5])
			vuln.DataConfidentiality = utils.TrimNull(cvssDesc[6])
			vuln.DataIntegrity = utils.TrimNull(cvssDesc[7])
			vuln.ServerHazards = utils.TrimNull(cvssDesc[8])
			num, err := utils.FormatNum(cvssDesc[9])
			if err != nil {
				log.Fatal().Str("全网数量", cvssDesc[9]).
					Msgf("failed to convert num:%v", err)
				return
			}
			vuln.NetworkNum = num
		}
	})
	// 获取CWE数据
	c.OnHTML("div.card__content > div.table-responsive > table.table", func(e *colly.HTMLElement) {
		cwe := e.ChildTexts("tbody > tr > td")
		if cwe == nil {
			return
		}
		if cwe[0] == "" {
			vuln.Type = nil
		} else {
			vulnType := &model.VulnType{CweId: cwe[0], Value: cwe[1]}
			vuln.Type = vulnType
		}
	})

	if err := c.Visit(utils.AddQuery(url, map[string]string{QueryId: vulnId}).String()); err != nil {
		return nil, err
	}

	return &vuln, nil
}
