# TSecret Operator Makefile

IMG ?= tsecret-operator:latest
NAMESPACE ?= tsecret-system

.PHONY: all build run test docker-build docker-push install uninstall deploy manifests generate fmt vet

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
helm-install:
	helm install tsecret ./charts/tsecret -n $(NAMESPACE) --create-namespace

helm-uninstall:
	helm uninstall tsecret -n $(NAMESPACE)

helm-template:
	helm template tsecret ./charts/tsecret -n $(NAMESPACE)
