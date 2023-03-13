package ainur

import (
	"debug/elf"
	"errors"
	"strings"
)

// Static checks that PT_DYNAMIC is not in one of the prog headers of the ELF file
func Static(f *elf.File) bool {
	for _, prog := range f.Progs {
		progType := prog.ProgHeader.Type
		if progType == elf.PT_DYNAMIC {
			return false
		}
	}
	return true
}

// ExamineStatic examines a given filename and returns true if is statically linked
// (does not have PT_DYNAMIC in one of the prog headers)
func ExamineStatic(filename string) (bool, error) {
	f, err := elf.Open(filename)
	if err != nil {
		if strings.HasPrefix(err.Error(), "bad magic") {
			return false, errors.New(filename + ": Not an ELF")
		}
		return false, err
	}
	defer f.Close()
	return Static(f), nil
}

// MustExamineStatic does the same as ExamineStatic, but panics instead of returning an error
func MustExamineStatic(filename string) bool {
	static, err := ExamineStatic(filename)
	if err != nil {
		panic(err)
	}
	return static
}
