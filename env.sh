#! /usr/bin/env bash
# Copyright (c) 2022 The Parca Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -euo pipefail

go install github.com/brancz/gojsontoyaml@latest

go install github.com/google/go-jsonnet/cmd/jsonnet@latest

go install github.com/google/go-jsonnet/cmd/jsonnetfmt@latest

go install github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@latest

go install github.com/campoy/embedmd@latest

go install mvdan.cc/gofumpt@latest

go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.45.0
