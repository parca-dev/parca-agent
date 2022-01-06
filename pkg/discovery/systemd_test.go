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
