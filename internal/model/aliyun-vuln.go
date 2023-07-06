package model

import "time"

type MetaData struct {
	LastUpdate time.Time `json:"last_update,omitempty"` // 上次更新时间

	CategoryVuln map[string]int `json:"category_vuln"` // 各类漏洞总数
	CveVuln      int            `json:"cve_vuln"`      // CVE漏洞总数
	NonCveVuln   int            `json:"non_cve_vuln"`  // 非CVE总数
	TotalVuln    int            `json:"total_vuln"`    // 漏洞总数
}

type VulnDetail struct {
	VulnList
	AvdSeverity   string                 `json:"avd_severity,omitempty"`   // 阿里云安全等级
	NvdLink       string                 `json:"nvd_link,omitempty"`       // NVD 链接
	ExploitState  string                 `json:"exploit_state,omitempty"`  // 利用情况
	PatchState    string                 `json:"patch_state,omitempty"`    // 补丁情况
	Description   string                 `json:"description,omitempty"`    // 漏洞描述
	FixSuggestion string                 `json:"fix_suggestion,omitempty"` // 解决建议
	References    []string               `json:"references,omitempty"`     // 参考链接
	AffectStates  []*AffectSoftwareState `json:"affect_state,omitempty"`   // 受影响软件情况

	AvdScore            float64 `json:"avd_score,omitempty"`            // 阿里云评分
	AttackPath          string  `json:"attack_path,omitempty"`          // 攻击路径
	AttackComplex       string  `json:"attack_complex,omitempty"`       // 攻击复杂度
	PermissionRequire   string  `json:"permission_require,omitempty"`   // 权限要求
	AffectScope         string  `json:"affect_scope,omitempty"`         // 影响范围
	ExpMaturity         string  `json:"exp_maturity,omitempty"`         // EXP 成熟度
	DataIntegrity       string  `json:"data_integrity,omitempty"`       // 数据完整性
	DataConfidentiality string  `json:"data_confidentiality,omitempty"` // 数据保密性
	ServerHazards       string  `json:"server_hazards,omitempty"`       // 服务器危害
	NetworkNum          int     `json:"network_num,omitempty"`          // 全网数量
	UserInteraction     string  `json:"user_interaction,omitempty"`     // 用户交互
	Availability        string  `json:"availability,omitempty"`         // 可用性
	Confidentiality     string  `json:"confidentiality,omitempty"`      // 保密性
	Integrity           string  `json:"integrity,omitempty"`            // 完整性
}

type VulnList struct {
	CveId       string    `json:"cve_id,omitempty"`       // CVE 编号
	AvdId       string    `json:"avd_id,omitempty"`       // 阿里云漏洞编号
	Name        string    `json:"name,omitempty"`         // 漏洞名称
	Type        *VulnType `json:"type,omitempty"`         // 漏洞类型
	PublishTime string    `json:"publish_time,omitempty"` // 披露时间
	CvssScore   float64   `json:"cvss_score,omitempty"`   // CVSS 分数
	AvdLink     string    `json:"avd_link,omitempty"`     // 阿里云漏洞详情链接
	Category    string    `json:"category,omitempty"`     // 漏洞分类
	Status      string    `json:"status,omitempty"`       // 漏洞状态
}

type VulnType struct {
	CweId string `json:"cwe_id,omitempty"` // CWE 编号
	Value string `json:"value,omitempty"`  // CWE 值
}

type AffectSoftwareState struct {
	Type    string `json:"type,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Scope   string `json:"scope,omitempty"`
}
