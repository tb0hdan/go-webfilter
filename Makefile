.PHONY: build

all: lint test build

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
