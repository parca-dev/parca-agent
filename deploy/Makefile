JSONNET_FMT := jsonnetfmt -n 2 --max-blank-lines 2 --string-style s --comment-style s
VERSION ?= $(shell git describe --exact-match --tags $$(git log -n1 --pretty='%h') 2>/dev/null || echo "$$(git rev-parse --abbrev-ref HEAD)-$$(git rev-parse --short HEAD)")
VERSION_GCP ?= $(shell echo "$(VERSION)" | sed -E 's/^v//; s/^([0-9]+\.[0-9]+).*/\1/')
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
		--push \
		--tag us-docker.pkg.dev/polar-signals-public/parca-agent/deployer:$(VERSION_GCP) \
		--provenance=false \
		--output type=image,oci-mediatypes=true \
		-f gcp/deployer/Dockerfile gcp
	crane mutate us-docker.pkg.dev/polar-signals-public/parca-agent/deployer:$(VERSION_GCP) --annotation com.googleapis.cloudmarketplace.product.service.name=services/parca-agent.endpoints.polar-signals-public.cloud.goog

.PHONY: parca-agent
parca-agent:
	docker buildx build \
		--push \
		--tag us-docker.pkg.dev/polar-signals-public/parca-agent/parca-agent:$(VERSION_GCP) \
		--tag us-docker.pkg.dev/polar-signals-public/parca-agent/parca-agent:$(VERSION_GCP) \
		--provenance=false \
		--output type=image,oci-mediatypes=true \
		-f gcp/parca-agent/Dockerfile gcp/parca-agent
	crane mutate us-docker.pkg.dev/polar-signals-public/parca-agent/parca-agent:$(VERSION_GCP) --annotation "com.googleapis.cloudmarketplace.product.service.name=services/parca-agent.endpoints.polar-signals-public.cloud.goog"
