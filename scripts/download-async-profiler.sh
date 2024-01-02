#!/usr/bin/env bash

# Copyright 2023-2024 The Parca Authors
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

set -euo pipefail

target_dir="${1:-goreleaser/dist/async-profiler}"
version="${2:-2.9}"

rm -rf "${target_dir}"
mkdir -p "${target_dir}"

wget -O - "https://github.com/async-profiler/async-profiler/releases/download/v${version}/async-profiler-${version}-linux-x64.tar.gz" | tar -xz -C "${target_dir}"

mkdir -p "${target_dir}/x64/libc"
mv "${target_dir}/async-profiler-${version}-linux-x64/build/jattach" "${target_dir}/x64/libc"
mv "${target_dir}/async-profiler-${version}-linux-x64/build/fdtransfer" "${target_dir}/x64/libc"
mv "${target_dir}/async-profiler-${version}-linux-x64/build/libasyncProfiler.so" "${target_dir}/x64/libc"
mv "${target_dir}/async-profiler-${version}-linux-x64/LICENSE" "${target_dir}/"
rm -rf "${target_dir}/async-profiler-${version}-linux-x64"
