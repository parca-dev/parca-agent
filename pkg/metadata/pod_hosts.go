package metadata

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prometheus/common/model"
)

var (
	hostname string
)

func init() {
	local, err := getExternalIpAndHost(1)
	if err != nil {
		panic(err)
	}
	hostname = local.hostname
}

// PodHosts provide host ip in default
// and will provide pod_ip and pod if pid is a pod
func PodHosts() Provider {
	return &StatelessProvider{"hosts", func(pid int) (model.LabelSet, error) {
		e, err := getExternalIpAndHost(pid)
		if err != nil {
			return nil, err
		}
		if hostname != e.hostname {
			// pod
			return model.LabelSet{
				"pod_ip": model.LabelValue(e.ip),
				"pod":    model.LabelValue(e.hostname),
			}, nil
		}
		return nil, nil
	}}
}

type hostEntry struct {
	ip       string
	hostname string
}

func getExternalIpAndHost(pid int) (*hostEntry, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/etc/hosts", pid))
	if err != nil {
		return nil, err
	}
	hostEntrys, err := parseHosts(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(hostEntrys) == 0 {
		return nil, fmt.Errorf("read hosts file result nil, raw:%s", string(data))
	}
	return &hostEntrys[len(hostEntrys)-1], nil
}

func parseHosts(r io.Reader) ([]hostEntry, error) {
	var res []hostEntry
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := string(s.Bytes())
		fileds := strings.Fields(line)
		if len(fileds) < 2 || fileds[0] == "#" {
			continue
		}
		res = append(res, hostEntry{
			ip:       fileds[0],
			hostname: fileds[1],
		})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
