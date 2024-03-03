// Copyright 2022-2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package runtime

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type IOVec struct {
	Base *byte
	Len  uint64
}

func CopyFromProcessMemory(pid int, addr uintptr, buf []byte) error {
	localIOV := IOVec{
		Base: &buf[0],
		Len:  uint64(len(buf)),
	}
	remoteIOV := IOVec{
		Base: (*byte)(unsafe.Pointer(addr)),
		Len:  uint64(len(buf)),
	}

	result, _, errno := syscall.Syscall6(unix.SYS_PROCESS_VM_READV, uintptr(pid),
		uintptr(unsafe.Pointer(&localIOV)), uintptr(1),
		uintptr(unsafe.Pointer(&remoteIOV)), uintptr(1),
		uintptr(0))

	if result == ^uintptr(0) { // -1 in unsigned representation
		//nolint:exhaustive
		switch errno {
		case syscall.ENOSYS, syscall.EPERM:
			procMem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
			if err != nil {
				return err
			}
			defer procMem.Close()

			_, err = procMem.Seek(int64(addr), 0)
			if err != nil {
				return err
			}

			_, err = procMem.Read(buf)
			return err
		default:
			return errno
		}
	}

	return nil
}
