package frame

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Spot check some of the constants.
func TestDWARFExpressionConstants(t *testing.T) {
	require.Equal(t, 0x0a, DW_OP_const2u)
	require.Equal(t, 0x2f, DW_OP_skip)
	require.Equal(t, 0x30, DW_OP_lit0)
	require.Equal(t, 0x9d, DW_OP_bit_piece)
	require.Equal(t, 0xe0, DW_OP_lo_user)
	require.Equal(t, 0xff, DW_OP_hi_user)
	require.Equal(t, 0x22, DW_OP_plus)
	require.Equal(t, 0x08, DW_OP_const1u)
}
