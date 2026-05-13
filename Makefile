# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

GOCMD ?= go
SRC_ROOT := $(shell git rev-parse --show-toplevel)
HACK_DIR := $(SRC_ROOT)/hack
SRC_DIRS := $(shell $(GOCMD) list -f '{{ .Dir }}' ./...)

TOOLS_MOD_DIR := $(SRC_ROOT)/internal/tools
TOOLS_MOD_FILE := $(TOOLS_MOD_DIR)/go.mod
GO_MODULE := $(shell $(GOCMD) list -m -f '{{ .Path }}' )
GO_TOOL := $(GOCMD) tool -modfile $(TOOLS_MOD_FILE)
LOCALBIN ?= $(SRC_ROOT)/bin

# Image URL to use all building/pushing image targets
IMAGE ?= ghcr.io/dnaeon/podcertificate-signer:latest

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

## Tool Binaries
KUBECTL ?= kubectl

# ENVTEST_K8S_VERSION configures the version of Kubernetes, which will be
# installed by setup-envtest.
#
# In order to configure the Kubernetes version to match the version used by the
# k8s.io/api package, use the following setting.
#
# ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{ printf "1.%d.%d", $$3, $$4 }')
#
# Or set the version here explicitly.
ENVTEST_K8S_VERSION ?= 1.36.0

# Kind cluster names.
KIND_CLUSTER_DEV ?= pcs-dev
KIND_CLUSTER_E2E ?= pcs-e2e

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: all
all: build

##@ Development

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: manifests
manifests:  ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(GO_TOOL) controller-gen rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate:  ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(GO_TOOL) controller-gen object:headerFile="$(HACK_DIR)/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	$(GOCMD) fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	$(GOCMD) vet ./...

.PHONY: test
test: manifests generate fmt vet  ## Run tests.
	@KUBEBUILDER_ASSETS="$$( $(GO_TOOL) setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path )" \
		$(GOCMD) test \
			-v \
			-race \
			-coverprofile=coverage.txt \
			-covermode=atomic \
			$(shell $(GOCMD) list ./...  | grep -v /e2e)

.PHONY: test-e2e
test-e2e: manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	@if ! $(GO_TOOL) kind get clusters | grep $(KIND_CLUSTER_E2E); then \
		echo "Creating e2e Kind cluster '$(KIND_CLUSTER_E2E)' ..."; \
		$(GO_TOOL) kind create cluster --name $(KIND_CLUSTER_E2E) --config $(SRC_ROOT)/kind/kind-config.yaml; \
	fi
	KIND_CLUSTER=$(KIND_CLUSTER_E2E) $(GOCMD) test -tags=e2e ./test/e2e/ -v -ginkgo.v
	@$(GO_TOOL) kind delete cluster --name $(KIND_CLUSTER_E2E)

.PHONY: lint
lint:  ## Run golangci-lint linter
	$(GO_TOOL) golangci-lint run

.PHONY: lint-fix
lint-fix:  ## Run golangci-lint linter and perform fixes
	$(GO_TOOL) golangci-lint run --fix

.PHONY: lint-config
lint-config:  ## Verify golangci-lint linter configuration
	$(GO_TOOL) golangci-lint config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet | $(LOCALBIN)  ## Build manager binary.
	$(GOCMD) build -o $(LOCALBIN)/manager cmd/podcertificate-signer/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	$(GOCMD) run ./cmd/podcertificate-signer/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMAGE} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMAGE}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMAGE=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMAGE=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name pcs-builder
	$(CONTAINER_TOOL) buildx use pcs-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMAGE} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm pcs-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate  ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(GO_TOOL) kustomize edit set image controller=${IMAGE}
	$(GO_TOOL) kustomize build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(GO_TOOL) kustomize build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(GO_TOOL) kustomize build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(GO_TOOL) kustomize edit set image controller=${IMAGE}
	$(GO_TOOL) kustomize build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy:  ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(GO_TOOL) kustomize build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -


##@ Helm Deployment

## Namespace to deploy the Helm release
HELM_NAMESPACE ?= pcs-system
## Name of the Helm release
HELM_RELEASE ?= podcertificate-signer
## Additional arguments to pass to helm commands
HELM_EXTRA_ARGS ?=

.PHONY: helm-deploy
helm-deploy:  ## Deploy manager to the K8s cluster via Helm. Specify an image with IMAGE env var.
	$(GO_TOOL) helm upgrade --install $(HELM_RELEASE) $(SRC_ROOT/charts/podcertificate-signer \
		--namespace $(HELM_NAMESPACE) \
		--create-namespace \
		--set image.repository=$${IMAGE%:*} \
		--set image.tag=$${IMAGE##*:} \
		--wait \
		--timeout 5m \
		$(HELM_EXTRA_ARGS)

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall the Helm release from the K8s cluster.
	$(GO_TOOL) helm uninstall $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-status
helm-status: ## Show Helm release status.
	$(GO_TOOL) helm status $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-history
helm-history: ## Show Helm release history.
	$(GO_TOOL) helm history $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)

.PHONY: helm-rollback
helm-rollback: ## Rollback to previous Helm release.
	$(GO_TOOL) helm rollback $(HELM_RELEASE) --namespace $(HELM_NAMESPACE)
