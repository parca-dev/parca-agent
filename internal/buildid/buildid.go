package buildid

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	gnuBuildIDNoteName = "GNU\x00"
	gnuBuildIDNoteType = 3
)

var ErrNotFound = errors.New("GNU build ID not found")

// Clean treats build IDs as C strings. This removes the trailing NUL byte that
// Go build IDs can carry when read directly from ELF notes.
func Clean(buildID string) string {
	if idx := strings.IndexByte(buildID, 0); idx >= 0 {
		return buildID[:idx]
	}
	return buildID
}

// Resolve prefers the executable's GNU build ID when the file is available,
// falling back to a cleaned build ID captured earlier by the caller.
func Resolve(executablePath, fallback string) string {
	if executablePath != "" {
		if buildID, err := GNU(executablePath); err == nil && buildID != "" {
			return buildID
		}
	}
	return Clean(fallback)
}

// GNU reads the GNU build ID from an ELF executable.
func GNU(executablePath string) (string, error) {
	f, err := elf.Open(executablePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, section := range f.Sections {
		if section.Type != elf.SHT_NOTE {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return "", fmt.Errorf("read note section %s: %w", section.Name, err)
		}

		buildID, ok, err := gnuFromNotes(data, f.ByteOrder, section.Addralign)
		if err != nil {
			return "", fmt.Errorf("parse note section %s: %w", section.Name, err)
		}
		if ok {
			return buildID, nil
		}
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_NOTE {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(prog.Open(), int64(prog.Filesz)))
		if err != nil {
			return "", fmt.Errorf("read note program: %w", err)
		}

		buildID, ok, err := gnuFromNotes(data, f.ByteOrder, prog.Align)
		if err != nil {
			return "", fmt.Errorf("parse note program: %w", err)
		}
		if ok {
			return buildID, nil
		}
	}

	return "", ErrNotFound
}

func gnuFromNotes(data []byte, order binary.ByteOrder, alignment uint64) (string, bool, error) {
	for len(data) >= 12 {
		nameSize := order.Uint32(data[0:4])
		descSize := order.Uint32(data[4:8])
		noteType := order.Uint32(data[8:12])

		nameStart := uint64(12)
		nameEnd := nameStart + uint64(nameSize)
		if nameEnd > uint64(len(data)) {
			return "", false, io.ErrUnexpectedEOF
		}

		descStart := align(nameEnd, alignment)
		descEnd := descStart + uint64(descSize)
		if descEnd > uint64(len(data)) {
			return "", false, io.ErrUnexpectedEOF
		}

		name := data[nameStart:nameEnd]
		if noteType == gnuBuildIDNoteType && bytes.Equal(name, []byte(gnuBuildIDNoteName)) {
			return hex.EncodeToString(data[descStart:descEnd]), true, nil
		}

		next := align(descEnd, alignment)
		if next > uint64(len(data)) {
			break
		}
		if next == 0 {
			return "", false, errors.New("invalid ELF note alignment")
		}
		data = data[next:]
	}

	return "", false, nil
}

func align(offset, alignment uint64) uint64 {
	if alignment == 0 {
		alignment = 4
	}
	return (offset + alignment - 1) &^ (alignment - 1)
}
