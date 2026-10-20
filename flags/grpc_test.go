package flags

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// --debuginfo-address dials a second connection with the same registerer as
// the remote store's, which used to panic on the duplicate registration.
func TestRegisterClientMetricsSharesOneSetPerRegisterer(t *testing.T) {
	reg := prometheus.NewRegistry()

	first, err := registerClientMetrics(reg)
	require.NoError(t, err)
	second, err := registerClientMetrics(reg)
	require.NoError(t, err)

	require.Same(t, first, second)
}
