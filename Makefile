.PHONY: build

all: build-dir lint test build

build-dir:
	@echo "Creating build directory..."
	@mkdir -p build

lint:
	@echo "Running linters..."
	@golangci-lint run ./...

test:
	@echo "Running tests..."
	@go test -v ./... -coverprofile=build/coverage.out
	@go tool cover -html=build/coverage.out -o build/coverage.html

build:
	@echo "Building the project..."
	@go build -o build/go-webfilter ./cmd/webfilter/*.go

tools:
	@echo "Running tools..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v2.2.1
