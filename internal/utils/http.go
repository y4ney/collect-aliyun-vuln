package utils

import (
	"golang.org/x/xerrors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func URL(scheme, host, path string) *url.URL {
	return &url.URL{Scheme: scheme, Host: host, Path: path}
}
func AddQuery(URL *url.URL, params map[string]string) *url.URL {
	queryParams := url.Values{}
	for param, value := range params {
		queryParams.Set(param, value)
	}
	URL.RawQuery = queryParams.Encode()

	return URL
}
func ParseLink(URL url.URL, text string) (string, string) {
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

func TrimNull(text string) string {
	if text == "N/A" || text == "未定义" || text == "暂无" {
		return ""
	}
	return text
}

func FormatScore(text string) (float64, error) {
	if text == "N/A" || text == "未定义" || text == "暂无" {
		return 0, nil
	}
	score, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, xerrors.Errorf("failed to convert %s:%w", text, err)
	}

	return score, nil
}

func FormatNum(text string) (int, error) {
	if text == "N/A" || text == "未定义" {
		return 0, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, xerrors.Errorf("failed to convert %s:%w", text, err)
	}
	return n, nil
}

func IsCVECode(str string) bool {
	// 使用正则表达式进行匹配
	match, _ := regexp.MatchString(`^CVE-\d{4}-\d{4,}$`, str)
	return match
}
