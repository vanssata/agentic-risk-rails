GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint fmt check
build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o rr ./cmd/rr

test:
	$(GO) test ./... -race

fmt:
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run ./...

# Gate for every wave and every agent's acceptance.
check: fmt
	$(GO) vet ./...
	$(MAKE) lint
	$(MAKE) test
