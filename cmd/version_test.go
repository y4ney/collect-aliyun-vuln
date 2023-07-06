package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/y4ney/collect-aliyun-vuln/internal/config"
)

func TestVersion(t *testing.T) {
	mock := &stdoutMock{buf: bytes.Buffer{}}
	out = mock

	config.AppName = "COLLECT ALIYUN VULN"
	config.AppVersion = "1.0.0"
	config.BuildTime = "2023-07-06T00:00:00Z"
	config.LastCommitHash = "1234567890"

	err := runPrintVersion(nil, []string{})
	assert.NoError(t, err)

	assert.Equal(t, expectedVersion, mock.buf.String())
}

var expectedVersion = `COLLECT ALIYUN VULN version 1.0.0
build date: 2023-07-06T00:00:00Z
commit: 1234567890

https://github.com/y4ney/collect-aliyun-vuln
`
