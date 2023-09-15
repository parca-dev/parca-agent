// Copyright 2022-2023 The Parca Authors
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

package interpreter

import (
	"errors"
	"fmt"

	"github.com/prometheus/procfs"

	"github.com/parca-dev/parca-agent/pkg/runtime"
	"github.com/parca-dev/parca-agent/pkg/runtime/python"
	"github.com/parca-dev/parca-agent/pkg/runtime/ruby"
)

// Fetch attempts to fetch interpreter information
// for each supported interpreter. Once one is found, it will be
// returned.
func Fetch(p procfs.Proc) (*runtime.Interpreter, error) {
	interpreterType, err := determineInterpreterType(p)
	if err != nil {
		return nil, err
	}
	switch interpreterType {
	case runtime.InterpreterRuby:
		rubyInfo, err := ruby.InterpreterInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch ruby interpreter info: %w", err)
		}
		return rubyInfo, nil
	case runtime.InterpreterPython:
		pythonInfo, err := python.InterpreterInfo(p)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch python interpreter info: %w", err)
		}
		return pythonInfo, nil

	case runtime.InterpreterNone:
		return nil, nil //nolint: nilnil

	default:
		return nil, fmt.Errorf("unknown interpreter type: %v", interpreterType)
	}
}

func determineInterpreterType(proc procfs.Proc) (runtime.InterpreterType, error) {
	errs := errors.New("failed to determine intepreter")
	ok, err := ruby.IsInterpreter(proc)
	if ok {
		return runtime.InterpreterRuby, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}

	ok, err = python.IsInterpreter(proc)
	if ok {
		return runtime.InterpreterPython, nil
	}
	if err != nil {
		errs = errors.Join(errs, err)
	}
	return runtime.InterpreterNone, errs
}
