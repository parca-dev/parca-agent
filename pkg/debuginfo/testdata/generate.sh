#!/usr/bin/env bash

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

set -e

mkdir -p tmp
cd tmp
git clone git@github.com:kakkoyun/readelf-sections.git

cd readelf-sections
make build

objcopy --only-keep-debug readelf-sections readelf-sections.debug
strip -g readelf-sections
objcopy --add-gnu-debuglink=readelf-sections.debug readelf-sections

cd ../..
cp tmp/readelf-sections/readelf-sections.debug .
cp tmp/readelf-sections/readelf-sections .
