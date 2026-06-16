# TSecret Operator Makefile

IMG ?= tsecret-operator:latest
NAMESPACE ?= tsecret-system

.PHONY: all build run test docker-build docker-push install uninstall deploy manifests generate fmt vet \
	helm-lint helm-template helm-template-poc helm-package helm-install helm-install-poc helm-uninstall

all: build

## Build
build: fmt vet
	go build -o bin/manager ./cmd/manager

run: fmt vet
	go run ./cmd/manager

## Test
test:
	go test ./... -coverprofile cover.out

## Docker
docker-build:
	docker build -t $(IMG) .

docker-push:
	docker push $(IMG)

## Kubernetes
install: manifests
	kubectl apply -f config/crd/

uninstall:
	kubectl delete -f config/crd/

deploy: docker-build
	kubectl apply -f config/deploy/

## Code generation
manifests:
	@echo "CRD manifests are in config/crd/"

generate:
	@echo "Types are in pkg/apis/"

## Formatting
fmt:
	go fmt ./...

vet:
	go vet ./...

## Helm
HELM_CHART ?= ./charts/tsecret

helm-lint:
	helm lint $(HELM_CHART)

helm-template:
	helm template tsecret $(HELM_CHART) -n $(NAMESPACE)

helm-template-poc:
	helm template tsecret $(HELM_CHART) -n $(NAMESPACE) \
		--set poc.enabled=true \
		--set injection.enabled=true \
		--set 'injection.namespaces={default}'

helm-package:
	helm package $(HELM_CHART) -d dist/

helm-install:
	helm upgrade --install tsecret $(HELM_CHART) -n $(NAMESPACE) --create-namespace

helm-install-poc:
	helm upgrade --install tsecret $(HELM_CHART) -n $(NAMESPACE) --create-namespace \
		--set poc.enabled=true \
		--set injection.enabled=true \
		--set 'injection.namespaces={default}'

helm-uninstall:
	helm uninstall tsecret -n $(NAMESPACE)
