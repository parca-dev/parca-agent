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

PARCA=${PARCA:-../parca/bin/parca}
PARCA_AGENT=${PARCA_AGENT:-./dist/parca-agent}
DEBUG=${DEBUG:-''}

trap 'kill $(jobs -p); exit 0' EXIT

(
    $PARCA --config-path="./scripts/parca.yaml" --http-address=:7070 2>&1 | tee -i parca.log
) &

(
    if [ -z "$DEBUG" ]; then
        "${PARCA_AGENT}" \
            --node=local-test \
            --log-level=debug \
            --debuginfo-upload-timeout-duration=2m \
            --remote-store-address=localhost:7070 \
            --remote-store-insecure 2>&1 | tee -i parca-agent.log
    else
        printf "Starting parca-agent-debug\n"
        # Program will start and wait for debugger to attach.
        dlv --listen=:40000 --headless=true --api-version=2 --log --log-output=debugger,dap,rpc --accept-multiclient exec --continue -- \
            "${PARCA_AGENT}" \
            --node=local-test \
            --log-level=debug \
            --memlock-rlimit=0 \
            --remote-store-address=localhost:7070 \
            --remote-store-insecure 2>&1 | tee -i parca-agent.log
    fi
)
