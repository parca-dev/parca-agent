#!/usr/bin/env bash

# Copyright 2022-2023 The Parca Authors
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

# renovate: datasource=github-releases depName=parca-dev/parca
SERVER_VERSION='v0.19.0'

AGENT_VERSION="${1?Parca Agent version must be provided}"
KUBECONTEXT="${2?Kubernetes context must be provided}"

ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

KUBECTL=(kubectl --context="${KUBECONTEXT}")

function dump_deploy_status() {
    kubectl get all --all-namespaces

    echo ">>> Printing Parca logs..."
    "${KUBECTL[@]}" --namespace=parca logs --selector='app.kubernetes.io/name=parca'

    echo '>>> Printing Parca Agent logs...'
    "${KUBECTL[@]}" --namespace=parca logs --selector='app.kubernetes.io/name=parca-agent'
}

# Configure clusters to run latest commit in Parca agent
function deploy() {
    trap dump_deploy_status EXIT

    if ! "${KUBECTL[@]}" get namespace parca >/dev/null; then
        "${KUBECTL[@]}" create namespace parca
    fi

    make -C deploy vendor
    jsonnet \
        --tla-str version="${AGENT_VERSION}" \
        --tla-str serverVersion="${SERVER_VERSION}" \
        --jpath deploy/vendor \
        deploy/e2e.jsonnet \
        | kubectl apply --filename=-

    "${KUBECTL[@]}" --namespace=parca rollout status deployment/parca --timeout=2m
    "${KUBECTL[@]}" --namespace=parca rollout status daemonset/parca-agent --timeout=2m

    echo '>>> Profiling system for 5 minutes...'
    sleep 300
}

function main() {
    deploy
}

main "${@}"
