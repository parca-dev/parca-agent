package metadata

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHost(t *testing.T) {
	testData := `
# Kubernetes-managed hosts file.
127.0.0.1       localhost

10.14.218.32    parca-agent-25q5t
`
	result, err := parseHosts(strings.NewReader(testData))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []hostEntry{
		{
			ip:       "127.0.0.1",
			hostname: "localhost",
		},
		{
			ip:       "10.14.218.32",
			hostname: "parca-agent-25q5t",
		},
	}, result)
}
