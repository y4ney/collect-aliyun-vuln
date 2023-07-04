package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"net/url"
	"reflect"
	"testing"
)

func TestCollector_GetVulnList(t *testing.T) {
	var d []*model.VulnList
	if err := utils.ReadFile("./testdata/cve-vuln-list.json", &d); err != nil {
		panic(err)
	}
	type fields struct {
		c   *colly.Collector
		url *url.URL
	}
	type args struct {
		category string
		page     int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []*model.VulnList
		wantErr bool
	}{
		{
			name: "测试爬取CVE漏洞中的操作系统类型漏洞第1页",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, CvdVulnListPath),
			},
			args: args{
				category: OS,
				page:     1,
			},
			want:    d,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetVulnList(tt.args.category, tt.args.page)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVulnList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVulnList() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollector_GetMetaData(t *testing.T) {
	type fields struct {
		c   *colly.Collector
		url *url.URL
	}
	type args struct {
		category string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Page
		wantErr bool
	}{
		{
			name: "test for metadata of os",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, CvdVulnListPath),
			},
			args:    args{OS},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetMetaData(tt.args.category)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMetaData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMetaData() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollector_GetVulnDetail(t *testing.T) {
	var d model.VulnDetail
	if err := utils.ReadFile("./testdata/AVD-2021-21107.json", &d); err != nil {
		panic(err)
	}
	type fields struct {
		c   *colly.Collector
		url *url.URL
	}
	type args struct {
		vulnId string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *model.VulnDetail
		wantErr bool
	}{
		{
			name: "test for vuln detail",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, VulnDetailPath),
			},
			args:    args{"AVD-2021-21107"},
			want:    &d,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetVulnDetail(tt.args.vulnId)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetVulnDetail() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetVulnDetail() got = %v, want %v", got, tt.want)
			}
		})
	}
}
