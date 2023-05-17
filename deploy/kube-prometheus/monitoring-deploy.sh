#!/usr/bin/env bash
set -euo pipefail

PARENT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${PARENT_DIR}"

kubectl apply --server-side -f ./manifests/setup
until kubectl get servicemonitors --all-namespaces; do
    date
    sleep 1
    echo
done

kubectl apply -f ./manifests/
