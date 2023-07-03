package model

type Vuln struct {
	VulnOverview
	References []string `json:"references"` // TODO 别忘了，还有NVD的链接
}

type VulnOverview struct {
	CveId       string    `json:"cve_id,omitempty"`
	AvdId       string    `json:"avd_id,omitempty"`
	Name        string    `json:"name,omitempty"`
	Type        *VulnType `json:"type,omitempty"`
	PublishTime string    `json:"publish_time,omitempty"`
	CvssScore   float64   `json:"cvss_score,omitempty"`
	Link        string    `json:"link,omitempty"`
	Category    string    `json:"category,omitempty"`
	Status      string    `json:"status,omitempty"`
}

type VulnType struct {
	CweId string `json:"cwe_id,omitempty"`
	Value string `json:"value,omitempty"`
}
