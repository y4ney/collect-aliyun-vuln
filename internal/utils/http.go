package utils

import "net/url"

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
