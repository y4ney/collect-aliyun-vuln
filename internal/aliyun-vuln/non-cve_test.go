package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"net/url"
	"reflect"
	"testing"
)

func TestNonCveCollector_GetMetadata(t *testing.T) {
	type fields struct {
		c   *colly.Collector
		url *url.URL
	}
	tests := []struct {
		name    string
		fields  fields
		want    *model.MetaData
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &NonCveCollector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetMetadata()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMetadata() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNonCveCollector_GetPage(t *testing.T) {
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
			name: "Test for non cve vuln",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, NonCvdVulnListPath),
			},
			args: args{},
			want: &Page{
				Current: 1,
				Total:   2840,
				Record:  85181,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &NonCveCollector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetPage(tt.args.category)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPage() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNonCveCollector_GetVulnList(t *testing.T) {
	var vulns []*model.VulnList
	_ = utils.ReadFile("./testdata/non-cve-vuln-list.json", &vulns)
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
			name: "test for non cve vuln list",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, NonCvdVulnListPath),
			},
			args: args{
				category: "",
				page:     1,
			},
			want:    vulns,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &NonCveCollector{
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
