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

package unwinderinfo

import (
	"errors"
	"fmt"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/golang"
	"github.com/parca-dev/parca-agent/pkg/runtime/java"
	"github.com/parca-dev/parca-agent/pkg/runtime/python"
	"github.com/parca-dev/parca-agent/pkg/runtime/ruby"
)

// Fetch attempts to fetch unwinder information
// for each supported runtime. Once one is found, it will be
// returned.
func Fetch(p procfs.Proc, cim *runtime.CompilerInfoManager) (runtime.UnwinderInfo, error) {
	interpreterType, err := determineUnwinderType(p, cim)
	if err != nil {
		return nil, err
	}
	switch interpreterType {
	case runtime.UnwinderGo:
		goInfo, err := golang.RuntimeInfo(p, cim)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch go runtime info: %w", err)
		}
		return goInfo, nil
	case runtime.UnwinderRuby:
		rubyInfo, err := ruby.InterpreterInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch ruby interpreter info: %w", err)
		}
		return rubyInfo, nil
	case runtime.UnwinderPython:
		pythonInfo, err := python.InterpreterInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch python interpreter info: %w", err)
		}
		return pythonInfo, nil
	case runtime.UnwinderJava:
		jvmInfo, err := java.VMInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch jvm interpreter info: %w", err)
		}
		return jvmInfo, nil

	case runtime.UnwinderNone:
		return nil, nil //nolint: nilnil

	default:
		return nil, fmt.Errorf("unknown interpreter type: %v", interpreterType)
	}
}

func determineUnwinderType(proc procfs.Proc, cim *runtime.CompilerInfoManager) (runtime.UnwinderType, error) {
	errs := errors.New("failed to determine runtime unwinder type")
	ok, err := golang.IsRuntime(proc, cim)
	if ok {
		return runtime.UnwinderGo, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}
	ok, err = ruby.IsRuntime(proc)
	if ok {
		return runtime.UnwinderRuby, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}

	ok, err = python.IsRuntime(proc)
	if ok {
		return runtime.UnwinderPython, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}

	ok, err = java.IsRuntime(proc)
	if ok {
		return runtime.UnwinderJava, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}
	return runtime.UnwinderNone, errs
}
