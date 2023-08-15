package metadata

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	result, err := parseJavaVersion(strings.NewReader(`java version "1.8.0_144"
Java(TM) SE Runtime Environment (build 1.8.0_144-b01)
Java HotSpot(TM) 64-Bit Server VM (build 25.144-b01, mixed mode)
`))
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "1.8.0_144-b01", result)
}
