package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/google/martian/log"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"golang.org/x/xerrors"
	"net/url"
	"strconv"
	"strings"
)

const (
	QueryType       = "type"
	QueryPage       = "page"
	QueryId         = "id"
	cveVulnListPage = "body > main > div > div > div:nth-child(2) > div > span"
	cvdVulnList     = "body > main > div > div > div.my-3.px-3.pt-2.bg-white.rounded.shadow-sm.table-responsive > table"

	OS                = "操作系统"
	Database          = "数据库"
	Application       = "应用程序"
	WebApplication    = "WEB应用"
	HardwareEquipment = "硬件设备"
)

func (c *Collector) GetMetaData(category string) (*Page, error) {
	c.url = utils.AddQuery(c.url, map[string]string{QueryType: category})
	page, err := c.getPage(cveVulnListPage)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (c *Collector) GetVulnList(category string, page int) ([]*model.VulnList, error) {
	var vulns []*model.VulnList
	c.c.OnHTML(cvdVulnList, func(e *colly.HTMLElement) {
		e.ForEach(cvdVulnList+" > tbody > tr", func(_ int, row *colly.HTMLElement) {
			var vuln model.VulnList
			row.ForEachWithBreak(cvdVulnList+" > tbody > tr > td", func(index int, cell *colly.HTMLElement) bool {
				switch index {
				// 获取 CVE 编号和链接
				case 0:
					vuln.AvdLink, vuln.AvdId = parseLink(*c.url, cell.ChildAttr("a", "href"))
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
						s, err := strconv.ParseFloat(score, 64)
						if err != nil {
							log.Debugf("failed to convert %s:%w\n", s, err)
							return false
						}
						vuln.CvssScore = s
					}
				}
				return true
			})
			vuln.Category = category
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

func (c *Collector) GetVulnDetail(vulnId string) (*model.VulnDetail, error) {
	var vuln model.VulnDetail
	// 上方
	c.c.OnHTML("div.px-lg-5.px-3.py-lg-3.pt-4.bg-white", func(e *colly.HTMLElement) {
		title := e.ChildTexts("h5 > span")
		belowTitle := e.ChildTexts("div.metric-value")
		vuln.NvdLink = e.ChildAttr("a", "href")
		vuln.Category = e.ChildTexts("li")[1]
		vuln.AvdSeverity = title[0]
		vuln.Name = title[1]
		vuln.CveId = belowTitle[0]
		vuln.ExploitState = belowTitle[1]
		vuln.PatchState = belowTitle[2]
		vuln.PublishTime = belowTitle[3]
	})

	// 左下方
	c.c.OnHTML("div.py-4.pl-4.pr-4.px-2.bg-white.rounded.shadow-sm", func(e *colly.HTMLElement) {
		detail := e.ChildTexts("div.text-detail.pt-2.pb-4")
		vuln.Description = CleanText(detail[0])
		vuln.FixSuggestion = detail[1]
	})
	c.c.OnHTML("div.text-detail.pb-3.pt-2.reference", func(e *colly.HTMLElement) {
		vuln.References = e.ChildAttrs("a", "href")
	})
	c.c.OnHTML("div.pb-4.pt-3.table-responsive > table.table > tbody", func(e *colly.HTMLElement) {
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
					affectSoftware.Scope = CleanText(texts[5])
				}
				affectSoftwares = append(affectSoftwares, affectSoftware)
			}
			return true
		})
		vuln.AffectStates = affectSoftwares
	})

	// 右下方
	c.c.OnHTML("div.cvss-breakdown", func(e *colly.HTMLElement) {
		scoreSelector := "div.cvss-breakdown__score.cvss-breakdown__score--high"
		avdScore, err := strconv.ParseFloat(e.ChildText(scoreSelector), 64)
		if err != nil {
			log.Debugf("failed to convert %s:%w", e.ChildText(scoreSelector), err)
			return
		}
		vuln.AvdScore = avdScore
		cvssDesc := e.ChildTexts("div.cvss-breakdown__desc")
		vuln.AttackPath = cvssDesc[0]
		vuln.AttackComplex = cvssDesc[1]
		vuln.PermissionRequire = cvssDesc[2]
		vuln.AffectScope = cvssDesc[3]
		vuln.ExpMaturity = cvssDesc[4]
		vuln.PatchState = cvssDesc[5]
		vuln.DataConfidentiality = cvssDesc[6]
		vuln.DataIntegrity = cvssDesc[7]
		vuln.ServerHazards = cvssDesc[8]
		if cvssDesc[9] == "N/A" {
			vuln.NetworkNum = 0
		} else {
			n, err := strconv.Atoi(cvssDesc[9])
			if err != nil {
				log.Debugf("failed to convert %s:%w", cvssDesc[9], err)
			}
			vuln.NetworkNum = n
		}
	})
	c.c.OnHTML("div.card__content > div.table-responsive > table.table", func(e *colly.HTMLElement) {
		cwe := e.ChildTexts("tbody > tr > td")
		if cwe[0] == "" {
			vuln.Type = nil
		} else {
			vulnType := &model.VulnType{
				CweId: cwe[0],
				Value: cwe[1],
			}
			vuln.Type = vulnType
		}
	})

	if err := c.c.Visit(utils.AddQuery(c.url, map[string]string{QueryId: vulnId}).String()); err != nil {
		return nil, err
	}

	return &vuln, nil
}

func parseLink(URL url.URL, text string) (string, string) {
	URL.Path = ""
	URL.RawQuery = ""
	link := URL.String() + text
	return link, strings.Split(link, "=")[1]
}

func CleanText(text string) string {
	var strList []string
	for _, s := range strings.Split(text, "\n") {
		str := strings.TrimSpace(s)
		if str != "" {
			strList = append(strList, str)
		}
	}
	return strings.Join(strList, "\n")
}
