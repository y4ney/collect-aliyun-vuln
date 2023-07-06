package aliyun_vuln

import (
	"github.com/gocolly/colly/v2"
	"github.com/y4ney/collect-aliyun-vuln/internal/model"
	"github.com/y4ney/collect-aliyun-vuln/internal/utils"
	"reflect"
	"testing"
)

func Test_getPage(t *testing.T) {
	type args struct {
		url string
		c   *colly.Collector
	}
	tests := []struct {
		name    string
		args    args
		want    *Page
		wantErr bool
	}{
		{
			name: "test for getPage",
			args: args{
				url: utils.URL(Scheme, Domain, CvdVulnListPath).String(),
				c:   colly.NewCollector(),
			},
			want: &Page{
				Current: 1,
				Total:   7202,
				Record:  216035,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPage(tt.args.url, tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPage() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSearchVulnListNyName(t *testing.T) {
	var vulns []*model.VulnList
	_ = utils.ReadFile("./testdata/远程命令执行列表.json", &vulns)
	type args struct {
		vulnName string
	}
	tests := []struct {
		name    string
		args    args
		want    []*model.VulnList
		wantErr bool
	}{
		{
			name:    "Test for 远程命令执行漏洞",
			args:    args{"远程命令执行漏洞"},
			want:    vulns,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SearchVulnListByName(tt.args.vulnName)
			if (err != nil) != tt.wantErr {
				t.Errorf("SearchForName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SearchForName() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSearchVulnDetailByName(t *testing.T) {
	var vulns []*model.VulnDetail
	_ = utils.ReadFile("./testdata/远程命令执行详情.json", &vulns)
	type args struct {
		vulnName string
	}
	tests := []struct {
		name    string
		args    args
		want    []*model.VulnDetail
		wantErr bool
	}{
		{
			name:    "Test for 远程命令执行漏洞",
			args:    args{"远程命令执行漏洞"},
			want:    vulns,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SearchVulnDetailByName(tt.args.vulnName)
			if (err != nil) != tt.wantErr {
				t.Errorf("SearchVulnDetailByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SearchVulnDetailByName() got = %v, want %v", got, tt.want)
			}
		})
	}
}
