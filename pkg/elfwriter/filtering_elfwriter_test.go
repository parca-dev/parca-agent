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

package elfwriter

import (
	"debug/elf"
	"testing"
)

func TestFilteringWriter_Flush(t *testing.T) {
	type fields struct {
		Writer                  Writer
		src                     SeekReaderAt
		progPredicates          []func(*elf.Prog) bool
		sectionPredicates       []func(*elf.Section) bool
		sectionHeaderPredicates []func(*elf.Section) bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FilteringWriter{
				Writer:                  tt.fields.Writer,
				src:                     tt.fields.src,
				progPredicates:          tt.fields.progPredicates,
				sectionPredicates:       tt.fields.sectionPredicates,
				sectionHeaderPredicates: tt.fields.sectionHeaderPredicates,
			}
			if err := w.Flush(); (err != nil) != tt.wantErr {
				t.Errorf("Flush() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
