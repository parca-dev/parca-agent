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
#

################################################################################
#
# This script is meant to be run from the root of this project with the Makefile
#
################################################################################

# exit immediately when a command fails
set -e
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail
# error on unset variables
set -u

PARCA_AGENT=${PARCA_AGENT:-./dist/parca-agent}
REMOTE_STORE_ADDRESS=${REMOTE_STORE_ADDRESS:-grpc.polarsignals.com:443}
REMOTE_STORE_BEARER_TOKEN=${REMOTE_STORE_BEARER_TOKEN:-$(cat polarsignals.token)}
DEBUG=${DEBUG:-""}

(
    if [ -z "$DEBUG" ]; then
        sudo "${PARCA_AGENT}" \
            --http-address=":7072" \
            --node=remote-test \
            --log-level=debug \
            --bpf-verbose-logging \
            --enable-python-unwinding \
            --enable-ruby-unwinding \
            --config-path="parca-agent.yaml" \
            --remote-store-address="${REMOTE_STORE_ADDRESS}" \
            --remote-store-bearer-token="${REMOTE_STORE_BEARER_TOKEN}" 2>&1 | tee -i parca-agent.log
    else
        dlv --listen=:40000 --headless=true --api-version=2 --log --log-output=debugger,dap,rpc --accept-multiclient exec --continue -- \
            "${PARCA_AGENT}" \
            --http-address=":7072" \
            --node=remote-test \
            --log-level=debug \
            --memlock-rlimit=0 \
            --remote-store-address="${REMOTE_STORE_ADDRESS}" \
            --remote-store-bearer-token="${REMOTE_STORE_BEARER_TOKEN}" 2>&1 | tee -i parca-agent.log
    fi
)
