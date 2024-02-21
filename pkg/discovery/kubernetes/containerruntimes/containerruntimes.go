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

package containerruntimes

import (
	"encoding/json"
	"fmt"
	"regexp"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
)

// CRIClient defines the interface to interact with the container runtime interfaces.
type CRIClient interface {
	Close() error
	PIDFromContainerID(containerID string) (int, error)
}

func ParseOCIState(stateBuf []byte) (string, int, error) {
	ociState := &ocispec.State{}
	if err := json.Unmarshal(stateBuf, ociState); err != nil {
		// Some versions of runc produce an invalid json...
		// As a workaround, make it valid by trimming the invalid parts
		fix := regexp.MustCompile(`(?ms)^(.*),"annotations":.*$`)
		matches := fix.FindStringSubmatch(string(stateBuf))
		if len(matches) != 2 {
			err = fmt.Errorf("cannot parse OCI state: matches=%+v\n %w\n%s", matches, err, string(stateBuf))
			return "", 0, err
		}
		err = json.Unmarshal([]byte(matches[1]+"}"), ociState)
		if err != nil {
			err = fmt.Errorf("cannot parse OCI state: %w\n%s", err, string(stateBuf))
			return "", 0, err
		}
	}
	return ociState.ID, ociState.Pid, nil
}
