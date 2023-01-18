// Copyright 2022 The Parca Authors
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

package docker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docker/docker/client"
)

const (
	DefaultSocketPath = "/run/docker.sock"
	DefaultTimeout    = 2 * time.Second
)

type Client struct {
	client *client.Client
}

func NewDockerClient(path string) (*Client, error) {
	host := path
	if protoAddrParts := strings.SplitN(host, "://", 2); len(protoAddrParts) == 1 {
		// The default protocol is unix sockets (tcp and http are also valid).
		host = "unix://" + host
	}
	cli, err := client.NewClientWithOpts(
		client.WithHost(host),
		client.WithAPIVersionNegotiation(),
		client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", path, DefaultTimeout)
		}),
	)
	if err != nil {
		return nil, err
	}

	return &Client{
		client: cli,
	}, nil
}

func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

func (c *Client) PIDFromContainerID(containerID string) (int, error) {
	if !strings.HasPrefix(containerID, "docker://") {
		return -1, fmt.Errorf("invalid CRI %s, it should be docker", containerID)
	}

	containerID = strings.TrimPrefix(containerID, "docker://")

	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return -1, fmt.Errorf("failed to get container status, container id: %s: %w", containerID, err)
	}

	if containerJSON.State == nil {
		return -1, fmt.Errorf("container state is nil")
	}

	return containerJSON.State.Pid, nil
}
