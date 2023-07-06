package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunGenerateSchema(t *testing.T) {
	mock := &stdoutMock{buf: bytes.Buffer{}}
	out = mock

	err := runGenerateSchema(nil, []string{})
	assert.NoError(t, err)

	assert.Equal(t, expectedSchema, mock.buf.String())
}

type stdoutMock struct {
	buf bytes.Buffer
}

func (m *stdoutMock) Write(p []byte) (n int, err error) {
	return m.buf.Write(p)
}

func (m *stdoutMock) Close() error {
	return nil
}

var expectedSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/y4ney/collect-aliyun-vuln/internal/model/vuln-detail",
  "$ref": "#/$defs/VulnDetail",
  "$defs": {
    "AffectSoftwareState": {
      "properties": {
        "type": {
          "type": "string"
        },
        "vendor": {
          "type": "string"
        },
        "product": {
          "type": "string"
        },
        "version": {
          "type": "string"
        },
        "scope": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "VulnDetail": {
      "properties": {
        "cve_id": {
          "type": "string"
        },
        "avd_id": {
          "type": "string"
        },
        "name": {
          "type": "string"
        },
        "type": {
          "$ref": "#/$defs/VulnType"
        },
        "publish_time": {
          "type": "string"
        },
        "cvss_score": {
          "type": "number"
        },
        "avd_link": {
          "type": "string"
        },
        "category": {
          "type": "string"
        },
        "status": {
          "type": "string"
        },
        "avd_severity": {
          "type": "string"
        },
        "nvd_link": {
          "type": "string"
        },
        "exploit_state": {
          "type": "string"
        },
        "patch_state": {
          "type": "string"
        },
        "description": {
          "type": "string"
        },
        "fix_suggestion": {
          "type": "string"
        },
        "references": {
          "items": {
            "type": "string"
          },
          "type": "array"
        },
        "affect_state": {
          "items": {
            "$ref": "#/$defs/AffectSoftwareState"
          },
          "type": "array"
        },
        "avd_score": {
          "type": "number"
        },
        "attack_path": {
          "type": "string"
        },
        "attack_complex": {
          "type": "string"
        },
        "permission_require": {
          "type": "string"
        },
        "affect_scope": {
          "type": "string"
        },
        "exp_maturity": {
          "type": "string"
        },
        "data_integrity": {
          "type": "string"
        },
        "data_confidentiality": {
          "type": "string"
        },
        "server_hazards": {
          "type": "string"
        },
        "network_num": {
          "type": "integer"
        },
        "user_interaction": {
          "type": "string"
        },
        "availability": {
          "type": "string"
        },
        "confidentiality": {
          "type": "string"
        },
        "integrity": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    },
    "VulnType": {
      "properties": {
        "cwe_id": {
          "type": "string"
        },
        "value": {
          "type": "string"
        }
      },
      "additionalProperties": false,
      "type": "object"
    }
  }
}
`
