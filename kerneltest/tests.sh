#!/bin/bash
# Copyright 2024 The Parca Authors
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

# Meant to be run from the root of the repository
set -eu

kernel_version="5.4.276 5.10.217 5.15.159 6.1.91 6.8.10 6.9.1"

runtests=$(realpath "${OTEL_PROFILER}"/support/run-tests.sh)

cd kerneltest
install -d ci-kernels
for kernel_version in $kernel_version; do
    echo "FROM ghcr.io/cilium/ci-kernels:${kernel_version}" \
        | docker buildx build --quiet --pull --output="ci-kernels" -
    rm -rf ci-kernels/"${kernel_version}"/
    mv -f ci-kernels/boot/ ci-kernels/"${kernel_version}"/
    $runtests "${kernel_version}"
done
