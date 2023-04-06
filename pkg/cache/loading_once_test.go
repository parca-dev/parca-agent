package cache

import (
	"sync/atomic"
	"testing"

	"github.com/goburrow/cache"
	"github.com/stretchr/testify/require"
)

func TestLoadingOnceCache(t *testing.T) {
	var counter atomic.Uint32
	loader := func(key cache.Key) (cache.Value, error) {
		counter.Add(1)
		return "value", nil
	}
	c := NewLoadingOnceCache(loader)

	// First call loads value.
	for i := 0; i < 3; i++ {
		go func() {
			v, err := c.Get("key")
			require.NoError(t, err)
			require.Equal(t, "value", v)
		}()
	}
	v, err := c.Get("key")
	require.NoError(t, err)
	require.Equal(t, "value", v)

	require.Equal(t, uint32(1), counter.Load())
}
