package reporter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const Chinese string = "Go（又稱Golang[4]）是Google開發的一种静态强类型、編譯型、并发型，并具有垃圾回收功能的编程语言。"
const Chinese2 string = "Linux是一种自由和开放源码的类Unix操作系统。"

func TestMaybeFixTruncation(t *testing.T) {
	for _, test := range []struct {
		s      string
		result string
		ok     bool
	}{
		{"ASCII string", "ASCII string", true},
		// truncated, but too early -- can't be valid utf8
		{Chinese[0:4], "", false},
		// truncated at the limit, in the middle of a rune
		{Chinese[0:48], Chinese[0:47], true},
		// Too long string that happened to be
		// truncated on a rune boundary
		{Chinese2[0:48], Chinese2[0:48], true},
		// Too long string but valid UTF-8 --
		// the function should pass it through unscathed
		// (it is not responsible for doing its own truncation)
		{Chinese2, Chinese2, true},
	} {
		result, ok := maybeFixTruncation(test.s, 48)
		require.Equal(t, test.result, result)
		require.Equal(t, test.ok, ok)
	}
}
