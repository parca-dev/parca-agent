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

# Make sure the exported dashboard JSON wrapped with "{"dashboard": {...}}" and dashboard ID is set to null.
curl -X POST --insecure -H "Content-Type: application/json" -d @grafana-dashboard-api-export.json http://admin:admin@localhost:3000/api/dashboards/import
