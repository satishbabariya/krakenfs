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

# Run tests
.PHONY: test
test:
	go test ./...

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all       - Build Docker images (default)"
	@echo "  images    - Build Docker images"
	@echo "  publish   - Build and push Docker images"
	@echo "  test      - Run tests"
	@echo "  clean     - Clean build artifacts" 