// Copyright 2026 The Parca Authors
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

package gpumetrics

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// GPU identifies a device on the metrics about it.
type GPU struct {
	Index         int
	UUID          string
	Model         string
	DriverVersion string
}

// PutAttrs sets the attributes identifying g on a device metric.
func (g GPU) PutAttrs(attrs pcommon.Map) {
	g.PutIDAttrs(attrs)
	attrs.PutStr(attrHwType, "gpu")
	attrs.PutStr(attrHwVendor, "NVIDIA")
	if g.Model != "" {
		attrs.PutStr(attrHwModel, g.Model)
	}
	if g.DriverVersion != "" {
		attrs.PutStr(attrHwDriverVersion, g.DriverVersion)
	}
}

// PutIDAttrs sets just enough to say which GPU a per-process metric is about;
// the rest of the device's attributes are on its device metrics.
func (g GPU) PutIDAttrs(attrs pcommon.Map) {
	attrs.PutStr(attrHwID, g.UUID)
	// Named after the device node, /dev/nvidiaN, which is also nvidia-smi's
	// index.
	attrs.PutStr(attrHwName, fmt.Sprintf("nvidia%d", g.Index))
}
