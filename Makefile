BINARY_CLI    := agentsentry
BINARY_MCP    := agentsentry-mcp
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS       := -ldflags "-X main.version=$(VERSION) -s -w"

BUILD_DIR     := dist
CLI_PKG       := ./cmd/agentsentry
MCP_PKG       := ./cmd/mcpserver

GO            := go
GOTEST        := $(GO) test -race -count=1

# Docker / GHCR settings (override via env or CLI)
IMAGE_REPO    ?= ghcr.io/agentsafe-ai/agentsentry
IMAGE_TAG     ?= $(VERSION)

# Cross-compile targets: GOOS/GOARCH pairs
PLATFORMS     := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

COVERAGE_OUT  := coverage.out
COVERAGE_HTML := coverage.html
COVERAGE_MIN  ?= 60

.PHONY: all build build-cli build-mcp cross-compile \
        test test-verbose coverage coverage-html \
        lint fmt vet \
        docker docker-build docker-push \
        scan clean help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: compile both binaries into dist/
build: build-cli build-mcp

build-cli:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) $(CLI_PKG)

build-mcp:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_MCP) $(MCP_PKG)

## cross-compile: build all platform binaries into dist/
cross-compile:
	@mkdir -p $(BUILD_DIR)
	$(foreach PLATFORM,$(PLATFORMS), \
		$(eval GOOS=$(word 1,$(subst /, ,$(PLATFORM)))) \
		$(eval GOARCH=$(word 2,$(subst /, ,$(PLATFORM)))) \
		$(eval SUFFIX=$(if $(filter windows,$(GOOS)),.exe,)) \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(LDFLAGS) \
			-o $(BUILD_DIR)/$(BINARY_CLI)_$(GOOS)_$(GOARCH)$(SUFFIX) $(CLI_PKG); \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(LDFLAGS) \
			-o $(BUILD_DIR)/$(BINARY_MCP)_$(GOOS)_$(GOARCH)$(SUFFIX) $(MCP_PKG); \
	)
	@echo "Cross-compiled binaries in $(BUILD_DIR)/"

# ── Test ──────────────────────────────────────────────────────────────────────

## test: run all tests with race detector (required before every commit)
test:
	$(GOTEST) ./...

## test-verbose: run tests with verbose output
test-verbose:
	$(GOTEST) -v ./...

## coverage: run tests and show coverage summary; fail if below COVERAGE_MIN%
# cmd/ packages are integration wiring (no unit tests); coverage is measured
# only over pkg/ and internal/ where the business logic lives.
coverage:
	$(GOTEST) -coverprofile=$(COVERAGE_OUT) ./pkg/... ./internal/...
	@TOTAL=$$(go tool cover -func=$(COVERAGE_OUT) | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Coverage: $${TOTAL}% (minimum: $(COVERAGE_MIN)%)"; \
	if [ $$(echo "$${TOTAL} < $(COVERAGE_MIN)" | bc -l) -eq 1 ]; then \
		echo "FAIL: coverage below $(COVERAGE_MIN)%"; exit 1; \
	fi

## coverage-html: open an HTML coverage report in the browser
coverage-html: coverage
	$(GO) tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@echo "Coverage report: $(COVERAGE_HTML)"

# ── Quality ───────────────────────────────────────────────────────────────────

## lint: run golangci-lint (install: https://golangci-lint.run/usage/install/)
lint:
	golangci-lint run --timeout=5m ./...

## fmt: format all Go source files
fmt:
	$(GO) fmt ./...

## vet: run go vet
vet:
	$(GO) vet ./...

# ── Docker ────────────────────────────────────────────────────────────────────

## docker: build and tag the Docker image
docker: docker-build

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t $(IMAGE_REPO):$(IMAGE_TAG) \
		-t $(IMAGE_REPO):latest \
		.

## docker-push: push image to GHCR (requires docker login ghcr.io)
docker-push: docker-build
	docker push $(IMAGE_REPO):$(IMAGE_TAG)
	docker push $(IMAGE_REPO):latest

# ── AgentSentry Self-Scan ───────────────────────────────────────────────────────

## scan: run AgentSentry against testdata/tools.json and fail on blocked tools
scan: build-cli
	$(BUILD_DIR)/$(BINARY_CLI) scan --protocol mcp --input testdata/tools.json --fail-on block

# ── Misc ──────────────────────────────────────────────────────────────────────

## clean: remove build artefacts and coverage files
clean:
	rm -rf $(BUILD_DIR) $(COVERAGE_OUT) $(COVERAGE_HTML)

## help: list available make targets
help:
	@grep -E '^##' Makefile | sed 's/## /  /'
