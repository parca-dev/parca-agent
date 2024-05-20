//go:build arm64

package lua

func findOffsets(b []byte) (glrefOffset, curLOffset int, err error) {
	return 0x10, 0x170, nil
}
