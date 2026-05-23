.PHONY: build install clean test lint help

BINARY_NAME=adpack
VERSION=v0.3.0-dev
BUILD_DIR=bin
GO=go

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

install: build ## Install the binary to GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	$(GO) install
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME)
	@echo "Clean complete"

test: ## Run tests
	@echo "Running tests..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	@echo "Tests complete"

coverage: test ## Generate coverage report
	@echo "Generating coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...
	@echo "Lint complete"

fmt: ## Format code
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "Format complete"

vet: ## Run go vet
	@echo "Running go vet..."
	$(GO) vet ./...
	@echo "Vet complete"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GO) mod download
	@echo "Dependencies downloaded"

tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	$(GO) mod tidy
	@echo "Dependencies tidied"

run: build ## Build and run
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

all: clean deps fmt vet lint test build ## Run all checks and build
	@echo "All tasks complete"
