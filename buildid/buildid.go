package buildid

import (
	"errors"
	"fmt"
	"os"

	"github.com/polarsignals/polarsignals-agent/byteorder"
	"github.com/polarsignals/polarsignals-agent/internal/pprof/elfexec"
)

func KernelBuildID() (string, error) {
	f, err := os.Open("/sys/kernel/notes")
	if err != nil {
		return "", err
	}

	notes, err := elfexec.ParseNotes(f, 4, byteorder.GetHostByteOrder())
	if err != nil {
		return "", err
	}

	for _, n := range notes {
		if n.Name == "GNU" {
			return fmt.Sprintf("%x", n.Desc), nil
		}
	}

	return "", errors.New("kernel build id not found")
}

func ElfBuildID(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	b, err := elfexec.GetBuildID(f)
	if err != nil {
		return nil, err
	}

	return fmt.Sprintf("%x", n.Desc), nil
}
