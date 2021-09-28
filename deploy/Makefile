JSONNET_FMT := jsonnetfmt -n 2 --max-blank-lines 2 --string-style s --comment-style s
VERSION ?= $(shell cat git describe --exact-match --tags $$(git log -n1 --pretty='%h') 2>/dev/null || echo "$$(git rev-parse --abbrev-ref HEAD)-$$(git rev-parse --short HEAD)")

.PHONY: vendor
vendor:
	jb install

.PHONY: manifests
manifests: vendor $(shell find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
	rm -rf manifests
	mkdir -p manifests/openshift manifests/kubernetes
	jsonnet --tla-str version="$(VERSION)" -J vendor main.jsonnet -m manifests/kubernetes | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
	awk 'BEGINFILE {print "---"}{print}' manifests/kubernetes/* > manifests/kubernetes/manifest.yaml
	jsonnet --tla-str version="$(VERSION)" -J vendor openshift.jsonnet -m manifests/openshift | xargs -I{} sh -c 'cat {} | gojsontoyaml > {}.yaml; rm -f {}' -- {}
	awk 'BEGINFILE {print "---"}{print}' manifests/openshift/* > manifests/openshift/manifest.yaml

fmt:
	find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print | \
		xargs -n 1 -- $(JSONNET_FMT) -i
