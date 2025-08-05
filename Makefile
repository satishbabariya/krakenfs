SHELL = /bin/bash -o pipefail
GO = go

# Flags to pass to go build
BUILD_FLAGS = -gcflags '-N -l'
BUILD_QUIET ?= -q

GOLANG_IMAGE ?= golang:1.21
GOPROXY ?= $(shell go env GOPROXY)

# Where to find your project
PROJECT_ROOT = github.com/uber/krakenfs
PACKAGE_VERSION ?= $(shell git describe --always --tags)

ALL_SRC = $(shell find . -name "*.go" | grep -v \
	-e ".*/\..*" \
	-e ".*/_.*" \
	-e ".*/mocks.*")

ALL_PKGS = $(shell go list $(sort $(dir $(ALL_SRC))))

# ==== BASIC ====

ifdef RUNNER_WORKSPACE
REPO_ROOT := $(RUNNER_WORKSPACE)/krakenfs
else
REPO_ROOT := $(CURDIR)
endif

UNAME_S := $(shell uname -s)

# Cross compiling cgo for sqlite3 is not well supported in Mac OSX.
# This workaround builds the binary inside a linux container.
# However, for tools like puller that don't use cgo, we can build natively on macOS.
CROSS_COMPILER = \
  docker run --rm \
    -v $(REPO_ROOT):/app \
    -w /app \
    -e GIT_SSL_NO_VERIFY=true \
    -e GOPROXY=$(GOPROXY) \
    -e GOSUMDB=off \
    -e GOINSECURE="*" \
    -e GO111MODULE=on \
    $(GOLANG_IMAGE) \
    go build -o ./$@ ./$(dir $@);

NATIVE_COMPILER = GOOS=$(shell echo $(UNAME_S) | tr '[:upper:]' '[:lower:]') GOARCH=amd64 go build -o $@ ./$(dir $@)

# Binaries that require Linux build
LINUX_BINS = \
    cmd/main/main \
    cmd/krakenfs-agent/krakenfs-agent

REGISTRY ?= gcr.io/uber-container-tools

$(LINUX_BINS): $(ALL_SRC)
	$(CROSS_COMPILER)

define tag_image
	docker tag $(1):$(PACKAGE_VERSION) $(1):dev
	docker tag $(1):$(PACKAGE_VERSION) $(REGISTRY)/$(1):$(PACKAGE_VERSION)
endef

.PHONY: images
images: $(LINUX_BINS)
	docker build $(BUILD_QUIET) -t krakenfs:$(PACKAGE_VERSION) -f docker/krakenfs/Dockerfile ./
	$(call tag_image,krakenfs)

.PHONY: publish
publish: images
	docker push $(REGISTRY)/krakenfs:$(PACKAGE_VERSION)

.PHONY: test
test:
	$(GO) test ./...

.PHONY: example
example:
	$(GO) run examples/simple/main.go

.PHONY: deploy
deploy:
	chmod +x scripts/deploy.sh
	./scripts/deploy.sh

.PHONY: build-agent
build-agent:
	$(GO) build -o bin/krakenfs-agent ./cmd/krakenfs-agent

.PHONY: clean
clean:
	rm -f $(LINUX_BINS)
	docker rmi krakenfs:$(PACKAGE_VERSION) 2>/dev/null || true

.PHONY: dev
dev: images
	docker-compose -f examples/docker-compose.yml up -d

.PHONY: dev-stop
dev-stop:
	docker-compose -f examples/docker-compose.yml down

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  images     - Build Docker images"
	@echo "  publish    - Build and push Docker images"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  dev        - Start development environment"
	@echo "  dev-stop   - Stop development environment" 