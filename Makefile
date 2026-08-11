# xai-oauth — common developer targets
#
#   make          # same as make help
#   make build    # ./xai-oauth
#   make test
#   make check    # fmt-check + vet + test

BIN      ?= xai-oauth
CMD      := ./cmd/xai-oauth
PKG      := ./...
PREFIX   ?= $(HOME)/.local
BINDIR   ?= $(PREFIX)/bin

GO       ?= go
GOFLAGS  ?=
LDFLAGS  ?=

COVERPROFILE ?= coverage.out

.PHONY: help all build install uninstall \
	test test-race cover vet fmt fmt-check tidy check clean version

.DEFAULT_GOAL := help

help: ## Show this help
	@printf 'Usage: make <target>\n\n'
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: build ## Build the CLI binary

build: ## Build ./xai-oauth from cmd/xai-oauth
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) $(CMD)

install: build ## Install binary to $(BINDIR) (default: ~/.local/bin)
	install -d $(BINDIR)
	install -m 755 $(BIN) $(BINDIR)/$(BIN)

uninstall: ## Remove binary from $(BINDIR)
	rm -f $(BINDIR)/$(BIN)

test: ## Run all unit tests
	$(GO) test $(GOFLAGS) $(PKG)

test-race: ## Run tests with the race detector
	$(GO) test $(GOFLAGS) -race $(PKG)

cover: ## Run tests with coverage report (coverage.out + func summary)
	$(GO) test $(GOFLAGS) -coverprofile=$(COVERPROFILE) -covermode=atomic $(PKG)
	$(GO) tool cover -func=$(COVERPROFILE)

vet: ## Run go vet
	$(GO) vet $(GOFLAGS) $(PKG)

fmt: ## Format all Go sources (gofmt -w)
	@gofmt -w $$(find . -name '*.go' -not -path './.git/*')

fmt-check: ## Fail if gofmt would change files
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './.git/*')); \
	if [ -n "$$out" ]; then \
		printf 'gofmt needed on:\n%s\n' "$$out"; \
		exit 1; \
	fi

tidy: ## go mod tidy
	$(GO) mod tidy

check: fmt-check vet test ## fmt-check + vet + test (CI-friendly)

clean: ## Remove build and coverage artifacts
	rm -f $(BIN) $(COVERPROFILE) coverage.html

version: build ## Print version via the built binary
	./$(BIN) version
