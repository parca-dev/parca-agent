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

package debuginfo

import (
	"github.com/parca-dev/parca-agent/pkg/objectfile"
)

type cache struct {
	files map[string]*debugInfoFile
}

func newCache() *cache {
	return &cache{
		files: make(map[string]*debugInfoFile),
	}
}

func (c *cache) debugInfoFile(objFile *objectfile.ObjectFile) *debugInfoFile {
	if dbgFile, ok := c.files[objFile.BuildID]; ok {
		return dbgFile
	}
	dbgInfoFile := debugInfoFile{ObjectFile: objFile}
	c.files[objFile.BuildID] = &dbgInfoFile
	return &dbgInfoFile
}
