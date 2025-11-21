#!/usr/bin/env bash
set -e

# Kubernetes
jsonnet --tla-str version="${VERSION}" -J vendor main.jsonnet -m manifests/kubernetes | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
for f in manifests/kubernetes/*; do cat ${f} >> manifests/kubernetes-manifest.yaml; echo '---' >> manifests/kubernetes-manifest.yaml; done
# OpenShift
jsonnet --tla-str version="${VERSION}" -J vendor openshift.jsonnet -m manifests/openshift | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
for f in manifests/openshift/*; do cat ${f} >> manifests/openshift-manifest.yaml; echo '---' >> manifests/openshift-manifest.yaml; done
# GCP Marketplace
jsonnet --tla-str version="${VERSION}" -J vendor gcp.jsonnet -m gcp/tmp | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
for f in gcp/tmp/*; do cat ${f} >> gcp/manifest/manifest.yaml.template; echo '---' >> gcp/manifest/manifest.yaml.template; done
# Tilt
jsonnet --tla-str serverVersion="${SERVER_VERSION}" -J vendor dev.jsonnet -m tilt | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}

