// Copyright (c) 2022 The Parca Authors
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

package kconfig

import (
	"testing"
)

func TestBpfConfig(t *testing.T) {
	isContainer, err := IsInContainer()
	if err != nil {
		t.Fatal("Check container error:", err)
	}

	if isContainer {
		t.Logf("Parca agent is running in a container. It'll need to access the host kernel config.")
		return
	}

	configPaths = []string{
		"/testdata/config",
		"/testdata/config.gz",
	}
	KernelConfig, e := getConfig()
	if e != nil {
		t.Logf("GetConfig error:%s", e.Error())
	}

	for _, option := range ebpfCheckOptions {
		value, found := KernelConfig[option]
		if !found {
			t.Logf("Kernel Config required for ebpf not found, Config Option:%s", option)
		}

		if value != "y" {
			t.Logf("Kernel Config required for ebpf is disabled, Config Option:%s", option)
		}
	}
	t.Logf("GetConfig success")
}
