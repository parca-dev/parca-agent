package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/parca-dev/parca-agent/build/tools"
	"github.com/parca-dev/parca-agent/build/version"
)

// Relative to the root of the repository.
const workingDirectory = "deploy"

var Default = Manifests.All

func findJsonnetFiles() ([]string, error) {
	files := []string{}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, "/vendor/") {
			return nil
		}
		if info.IsDir() {
			for _, ext := range []string{".libsonnet", ".jsonnet"} {
				matches, err := filepath.Glob(filepath.Join(path, fmt.Sprintf("*%s", ext)))
				if err != nil {
					return err
				}
				files = append(files, matches...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// Format formats the code.
func Format() error {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(fmt.Errorf("failed to change directory %s: %w", workingDirectory, err))
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(fmt.Errorf("failed to change directory %s: %w", pwd, err))
		}
	}()

	jsonnetFiles, err := findJsonnetFiles()
	if err != nil {
		return err
	}

	for _, f := range jsonnetFiles {
		if err := tools.RunGoTool(tools.JSONNETFMT, "-n", "2", "--max-blank-lines", "2", "--string-style", "s", "--comment-style", "s", "-i", f); err != nil {
			return err
		}
	}
	return nil
}

// Vendor installs the vendored dependencies.
func Vendor() error {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(fmt.Errorf("failed to change directory %s: %w", workingDirectory, err))
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(fmt.Errorf("failed to change directory %s: %w", pwd, err))
		}
	}()

	return tools.RunGoTool(tools.JB, "install")
}

type Manifests mg.Namespace

// All generates all the manifests.
func (Manifests) All() error {
	mg.SerialDeps(Vendor, Format)

	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(err)
		}
	}()

	agentVersion, err := version.Agent()
	if err != nil {
		return err
	}
	serverVersion, err := version.Server()
	if err != nil {
		return err
	}
	fmt.Println("Agent version:", agentVersion)
	fmt.Println("Server version:", serverVersion)

	mg.Deps(Manifests.Tilt, Manifests.Kubernetes, Manifests.OpenShift)
	return nil
}

// Tilt generates development manifests to be used with tilt.
func (Manifests) Tilt() error {
	mg.SerialDeps(Vendor, Format)

	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(err)
		}
	}()

	if err := sh.Rm("manifests"); err != nil {
		return err
	}
	if err := tools.RunGoTool(tools.JSONNET, "-J", "vendor", "-m", "manifests", "tilt.jsonnet"); err != nil {
		return err
	}
	return nil
}

// Kubernetes generates the manifests to be used with kubernetes.
func (Manifests) Kubernetes() error {
	mg.SerialDeps(Vendor, Format)

	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(err)
		}
	}()

	if err := sh.Rm("manifests"); err != nil {
		return err
	}
	if err := tools.RunGoTool(tools.JSONNET, "-J", "vendor", "-m", "manifests", "kubernetes.jsonnet"); err != nil {
		return err
	}
	return nil
}

// OpenShift generates the manifests to be used with openshift.
func (Manifests) OpenShift() error {
	mg.SerialDeps(Vendor, Format)

	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Chdir(pwd); err != nil {
			panic(err)
		}
	}()

	if err := sh.Rm("manifests"); err != nil {
		return err
	}
	if err := tools.RunGoTool(tools.JSONNET, "-J", "vendor", "-m", "manifests", "openshift.jsonnet"); err != nil {
		return err
	}
	return nil
}
