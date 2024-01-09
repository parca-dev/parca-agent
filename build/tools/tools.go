package tools

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const (
	// Compilers.
	GO  = "GO"
	CC  = "CC"
	CXX = "CXX"

	// Formatters.
	CLANG_FORMAT = "CLANG_FORMAT"

	// Helper Go tools.
	JSONNET    = "JSONNET"
	JSONNETFMT = "JSONNETFMT"
	JB         = "JB"
)

const (
	// Tool versions.
	// TODO(kakkoyun): Make sure renovate directives work as expected.

	// renovate: datasource=go depName=github.com/google/go-jsonnet
	JSONNET_VERSION = "v0.20.0"
	// renovate: datasource=go depName=github.com/jsonnet-bundler/jsonnet-bundler
	JB_VERSION = "v0.5.1"
)

var (
	// toolBinaries is a map of tool ENV vars to their default binary.
	// If the ENV var is not set, the default binary will be used.
	// If the default is NOT a path, it will be looked up in the PATH.
	toolBinaries = map[string]string{
		GO: mg.GoCmd(),
		// CC:           "zig cc",
		// CXX:          "zig c++",
		// CLANG_FORMAT: "clang-format",
	}
	// goToolBinaries is a map of go tool ENV vars to their default binary.
	// It will be run with `go run`.
	// e.g go run github.com/parca-dev/parca-agent/tree/main/cmd/eh-frame@latest.
	goToolBinaries = map[string]string{
		JSONNET:    fmt.Sprintf("github.com/google/go-jsonnet/cmd/jsonnet@%s", JSONNET_VERSION),
		JSONNETFMT: fmt.Sprintf("github.com/google/go-jsonnet/cmd/jsonnetfmt@%s", JSONNET_VERSION),
		JB:         fmt.Sprintf("github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@%s", JB_VERSION),
	}
)

// getToolKey returns the ENV var or the default binary.
func getToolKey(key string) string {
	if cmd := os.Getenv(key); cmd != "" {
		return cmd
	}
	if val, ok := toolBinaries[key]; ok {
		return val
	}
	panic(fmt.Errorf("no default binary for %s", key))
}

// bin returns the full path to the binary.
func bin(cmd string) string {
	exe := getToolKey(cmd)
	if strings.HasPrefix(exe, "./") || strings.HasPrefix(exe, "../") || strings.HasPrefix(exe, "/") {
		if _, err := os.Stat(exe); os.IsNotExist(err) {
			panic(fmt.Sprintf("binary %s does not exist: %s", cmd, exe))
		}
	}

	parts := strings.Split(exe, " ")
	if len(parts) > 1 {
		exe = parts[0]
	}
	if _, err := exec.LookPath(exe); err != nil {
		panic(fmt.Sprintf("binary %s does not exist in PATH: %s", cmd, exe))
	}

	return strings.Join(parts, " ")
}

// RunCmd runs the command with the given args.
func RunCmd(cmd string, args ...string) error {
	parts := strings.Split(cmd, " ")
	if len(parts) > 1 {
		return sh.Run(parts[0], append(parts[1:], args...)...)
	}
	return sh.Run(cmd, args...)
}

var (
	goRun    = sh.RunCmd(bin(GO), "run")
	goRunOut = sh.OutCmd(bin(GO), "run")
)

// RunGoTool runs the go tool with the given args.
func RunGoTool(cmd string, args ...string) error {
	return goRun(append([]string{goToolBinaries[cmd]}, args...)...)
}

// RunGoToolWithOutput runs the go tool with the given args and returns the output.
func RunGoToolWithOutput(cmd string, args ...string) (string, error) {
	return goRunOut(append([]string{goToolBinaries[cmd]}, args...)...)
}
