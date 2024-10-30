package elfwriter

import (
	"debug/elf"
	"fmt"
	"os"

	"go.opentelemetry.io/ebpf-profiler/process"
)

func OnlyKeepDebug(dst *os.File, src process.ReadAtCloser) error {
	w, err := NewNullifyingWriter(dst, src)
	if err != nil {
		return fmt.Errorf("initialize nullifying writer: %w", err)
	}
	w.FilterPrograms(func(p *elf.Prog) bool {
		return p.Type == elf.PT_NOTE
	})
	w.KeepSections(
		isDWARF,
		isSymbolTable,
		isGoSymbolTable,
		isPltSymbolTable, // NOTICE: gostd debug/elf.DWARF applies relocations.
		func(s *elf.Section) bool {
			return s.Name == ".comment"
		},
		func(s *elf.Section) bool {
			return s.Type == elf.SHT_NOTE
		},
	)

	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush ELF file: %w", err)
	}
	return nil
}
