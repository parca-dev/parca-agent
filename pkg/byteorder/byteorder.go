package byteorder

import (
	"encoding/binary"
	"unsafe"
)

var byteOrder binary.ByteOrder

// In lack of binary.HostEndian ...
func init() {
	byteOrder = determineHostByteOrder()
}

// GetHostByteOrder returns the current byte-order.
func GetHostByteOrder() binary.ByteOrder {
	return byteOrder
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
