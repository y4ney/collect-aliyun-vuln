package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/rs/zerolog/log"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"regexp"
	"strconv"
	"strings"
)

const (
	Scheme = "https"
	Domain = "avd.aliyun.com"

	QueryKeyword = "q"

	CvdVulnListPath    = "nvd/list"
	NonCvdVulnListPath = "nonvd/list"
	SearchPath         = "search"

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

func GetVulnDetail(vulnId string) (*model.VulnDetail, error) {
	// TODO cvssVector
	var vuln model.VulnDetail
	c := colly.NewCollector()
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
		vuln.PublishTime = utils.TrimNull(belowTitle[3])

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

	err := c.Visit(utils.AddQuery(utils.URL(Scheme, Domain, VulnDetailPath), map[string]string{QueryId: vulnId}).String())
	if err != nil {
		return nil, err
	}

	return &vuln, nil
}

// SearchForId 通过cve id或者是avd id查询漏洞详情
// TODO 写测试文件
func SearchForId(vulnId string) (*model.VulnDetail, error) {
	if utils.IsCVECode(vulnId) {
		vulnId = strings.ReplaceAll(vulnId, "CVE", "AVD")
	}
	vuln, err := GetVulnDetail(vulnId)
	if err != nil {
		return nil, xerrors.Errorf("failed to get detail for %s:%w", vulnId, err)
	}
	return vuln, nil
}

// SearchVulnListByName 通过 name 模糊查询漏洞列表
func SearchVulnListByName(vulnName string) ([]*model.VulnList, error) {
	url := utils.AddQuery(utils.URL(Scheme, Domain, SearchPath), map[string]string{QueryKeyword: vulnName})
	// 获取分页信息
	page, err := getPage(url.String(), colly.NewCollector())
	if err != nil {
		return nil, xerrors.Errorf("failed to get page of %s:%w", url.String(), err)
	}

	var vulns []*model.VulnList
	for i := page.Current; i <= page.Total; i++ {
		subVulns, err := getVulnListBySearch(vulnName, i)
		if err != nil {
			return nil, xerrors.Errorf("failed to get vuln list by search %s:%w", vulnName, err)
		}
		vulns = append(vulns, subVulns...)
	}

	return vulns, nil
}

// SearchVulnDetailByName 通过 name 模糊查询漏洞详情
func SearchVulnDetailByName(vulnName string) ([]*model.VulnDetail, error) {
	vulns, err := SearchVulnListByName(vulnName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get vuln list by %s", vulnName, err)
	}

	var vulnsDetail []*model.VulnDetail
	for _, vuln := range vulns {
		vulnDetail, err := GetVulnDetail(vuln.AvdId)
		if err != nil {
			return nil, xerrors.Errorf("failed to get vuln detail for %s", vuln.AvdId, err)
		}
		vulnsDetail = append(vulnsDetail, vulnDetail)
	}
	return vulnsDetail, nil
}

func getVulnListBySearch(vulnName string, page int) ([]*model.VulnList, error) {
	c := colly.NewCollector()
	url := utils.URL(Scheme, Domain, SearchPath)
	query := map[string]string{QueryPage: strconv.Itoa(page)}
	if vulnName == "" {
		url.Path = NonCvdVulnListPath
	} else {
		query[QueryKeyword] = vulnName
	}
	url = utils.AddQuery(url, query)
	var vulns []*model.VulnList
	c.OnHTML("table.table", func(e *colly.HTMLElement) {
		e.ForEach("tr", func(index int, row *colly.HTMLElement) {
			avdVuln := row.ChildTexts("td")
			if avdVuln == nil {
				return
			}
			vuln := model.VulnList{
				AvdId:       avdVuln[0],
				Name:        utils.TrimNull(avdVuln[1]),
				PublishTime: utils.TrimNull(avdVuln[3]),
			}
			vuln.AvdLink, _ = utils.ParseLink(*url, row.ChildAttr("a", "href"))
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
					if utils.IsCVECode(status) {
						vuln.CveId = status
					} else {
						vuln.Status = status
					}
				}
			}

			vulns = append(vulns, &vuln)
		})
	})

	err := c.Visit(url.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to request %s:%w", url.String(), err)
	}

	return vulns, nil
}
