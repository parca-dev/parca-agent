JSONNET_FMT := jsonnetfmt -n 2 --max-blank-lines 2 --string-style s --comment-style s
VERSION ?= $(shell git describe --exact-match --tags $$(git log -n1 --pretty='%h') 2>/dev/null || echo "$$(git rev-parse --abbrev-ref HEAD)-$$(git rev-parse --short HEAD)")
SERVER_VERSION ?= $(shell curl -s https://api.github.com/repos/parca-dev/parca/releases/latest | grep -oE '"tag_name":(.*)' | grep -o 'v[0-9.]*' | xargs echo -n)

.PHONY: vendor
vendor:
	jb install

.PHONY: manifests
manifests: vendor $(shell find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print)
	rm -rf manifests tilt gcp/manifest/manifest.yaml.template
	mkdir -p manifests/openshift manifests/kubernetes tilt
	export VERSION=$(VERSION) SERVER_VERSION=$(SERVER_VERSION) && ./generate.sh

fmt:
	find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print | \
		xargs -n 1 -- $(JSONNET_FMT) -i

.PHONY: deployer
deployer:
	docker buildx build \
		--output type=docker,name=us-docker.pkg.dev/polar-signals-public/parca-agent/deployer:0.44,push=true,oci-mediatypes=false \
		--annotation "index,manifest:com.googleapis.cloudmarketplace.product.service.name=services/parca-agent.endpoints.polar-signals-public.cloud.goog" \
		-f gcp/deployer/Dockerfile gcp

.PHONY: parca-agent
parca-agent:
	docker buildx build \
		--output type=docker,name=us-docker.pkg.dev/polar-signals-public/parca-agent/parca-agent:v0.44,push=true,oci-mediatypes=false \
		--annotation "index,manifest:com.googleapis.cloudmarketplace.product.service.name=services/parca-agent.endpoints.polar-signals-public.cloud.goog" \
		-f gcp/parca-agent/Dockerfile gcp/parca-agent
