#!/usr/bin/env bash

# Copyright 2022-2024 The Parca Authors
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

set -euox pipefail

mkdir -p ./tmp/e2e-dump
cd ./tmp/e2e-dump
touch kube-all kube-all.yaml
kubectl get all -A >kube-all
kubectl get all -A -o yaml >kube-all.yaml

list=$(kubectl get pods -A --template '{{range .items}}{{.metadata.namespace}} {{.metadata.name}}{{"\n"}}{{end}}')

IFS=$'\n'

for pod in $list; do
    #depending on logs, this may take a while
    #kubectl logs $pod > $pod.txt
    echo "$pod" | xargs -n2 sh -c "kubectl logs --all-containers --ignore-errors --namespace=$pod >> pod.logs"
done
