// Copyright 2021 The Parca Authors
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

package discovery

import (
	"context"
	"testing"

	"github.com/go-kit/log"

	"github.com/parca-dev/parca-agent/pkg/agent"
)

func TestReconcileUnitWithCgroupPath(t *testing.T) {
	service := "foobar.service"
	conf := NewSystemdConfig([]string{service}, "/sys/fs/cgroup/machine.slice/foobar/")
	dopts := DiscovererOptions{
		Logger: log.NewNopLogger(),
	}
	d, err := conf.NewDiscoverer(dopts)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := d.(*SystemdDiscoverer).ReconcileUnit(context.TODO(), service)
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 1 {
		t.Fatalf("expected 1 line, got %d", len(ls))
	}
	path, ok := ls[agent.CgroupPathLabelName]
	if !ok {
		t.Fatal("expected cgroup path label")
	}
	expected := "/sys/fs/cgroup/machine.slice/foobar/foobar.service"
	if string(path) != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}
