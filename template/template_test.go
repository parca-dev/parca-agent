package template

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/stretchr/testify/require"
)

func TestStatusPageTemplate(t *testing.T) {
	expected, err := os.ReadFile("testdata/statuspage.html")
	require.NoError(t, err)

	res := bytes.NewBuffer(nil)
	err = StatusPageTemplate.Execute(res, &StatusPage{
		ActiveProfilers: []ActiveProfiler{{
			Type: "test_profile_type",
			Labels: []labels.Label{{
				Name:  "name1",
				Value: "value1",
			}, {
				Name:  "name2",
				Value: "value2",
			}},
			LastTakenAgo: time.Second * 3,
			Error:        errors.New("test"),
			Link:         "/test123",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, string(expected), string(res.Bytes()))
}
