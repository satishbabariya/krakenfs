SHELL = /bin/bash -o pipefail

# Variables
PACKAGE_VERSION ?= $(shell git describe --always --tags 2>/dev/null || echo "dev")
REGISTRY ?= gcr.io/uber-container-tools
BUILD_QUIET ?= -q

# Docker image name
IMAGE_NAME = krakenfs

# Default target
.PHONY: all
all: images

# Build Docker image
.PHONY: images
images:
	docker build $(BUILD_QUIET) -t $(IMAGE_NAME):$(PACKAGE_VERSION) -f Dockerfile ./
	docker tag $(IMAGE_NAME):$(PACKAGE_VERSION) $(IMAGE_NAME):dev
	docker tag $(IMAGE_NAME):$(PACKAGE_VERSION) $(REGISTRY)/$(IMAGE_NAME):$(PACKAGE_VERSION)

# Push image to registry
.PHONY: publish
publish: images
	docker push $(REGISTRY)/$(IMAGE_NAME):$(PACKAGE_VERSION)

# Clean up
.PHONY: clean
clean:
	docker rmi $(IMAGE_NAME):$(PACKAGE_VERSION) 2>/dev/null || true

# Build binary
.PHONY: build
build:
	go build -o bin/krakenfs ./cmd/krakenfs

# Run development environment
.PHONY: dev
dev: build
	mkdir -p /tmp/krakenfs/config
	mkdir -p /tmp/krakenfs/data
	./bin/krakenfs --generate-config /tmp/krakenfs/config/krakenfs.yaml
	./bin/krakenfs --config /tmp/krakenfs/config/krakenfs.yaml

# Generate secure configuration
.PHONY: config
config:
	go run ./cmd/krakenfs --generate-config config/secure-config.yaml

# Validate configuration
.PHONY: validate-config
validate-config:
	go run ./cmd/krakenfs --validate-config config/krakenfs/example.yaml

# Run tests
.PHONY: test
test:
	go test ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Security scan
.PHONY: security
security:
	gosec ./...

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all            - Build Docker images (default)"
	@echo "  build          - Build binary"
	@echo "  images         - Build Docker images"
	@echo "  publish        - Build and push Docker images"
	@echo "  dev            - Run development environment"
	@echo "  config         - Generate secure configuration"
	@echo "  validate-config- Validate configuration security"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  security       - Security scan"
	@echo "  clean          - Clean build artifacts" 