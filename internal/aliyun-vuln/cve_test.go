package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"net/url"
	"reflect"
	"testing"
)

func TestCveCollector_GetPage(t *testing.T) {
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
			name: "test for get os page",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, CvdVulnListPath),
			},
			args: args{OS},
			want: &Page{
				Current: 1,
				Total:   1454,
				Record:  43610,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CveCollector{
				c:   tt.fields.c,
				url: tt.fields.url,
			}
			got, err := c.GetPage(tt.args.category)
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

func TestCveCollector_GetMetadata(t *testing.T) {
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
		{
			name: "test for get cve vuln metadata",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, CvdVulnListPath),
			},
			want: &model.MetaData{
				LastUpdate: now,
				CategoryVuln: map[string]int{
					WebApplication:    23806,
					Application:       135186,
					OS:                43610,
					Database:          1532,
					HardwareEquipment: 2167,
				},
				CveVuln: 206301,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CveCollector{
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

func TestCveCollector_GetVulnList(t *testing.T) {
	var vulns []*model.VulnList
	_ = utils.ReadFile("./testdata/cve-vuln-list.json", &vulns)
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
			name: "test for get cve vuln list",
			fields: fields{
				c:   colly.NewCollector(),
				url: utils.URL(Scheme, Domain, CvdVulnListPath),
			},
			args: args{
				category: OS,
				page:     1,
			},
			want:    vulns,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CveCollector{
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
