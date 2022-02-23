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

package objectfile

import "github.com/google/pprof/profile"

type Cache struct {
	files map[string]*ObjectFile
}

// NewCache creates a new cache for object files.
func NewCache() *Cache {
	return &Cache{
		files: make(map[string]*ObjectFile),
	}
}

// ObjectFileForProcess returns the object file for the given mapping and process id.
// If object file is already in the cache, it is returned.
// Otherwise, the object file is loaded from the file system.
func (c *Cache) ObjectFileForProcess(pid uint32, m *profile.Mapping) (*ObjectFile, error) {
	if objFile, ok := c.files[m.BuildID]; ok {
		return objFile, nil
	}
	objFile, err := FromProcess(pid, m)
	if err != nil {
		return nil, err
	}
	c.files[m.BuildID] = objFile
	return objFile, nil
}
