.DEFAULT_GOAL := help

SHELL := /bin/bash

GOPKG := github.com/veraison/gen-corim/...

GOLINT_ARGS ?= run --timeout=3m -E dupl -E gocritic -E staticcheck -E lll -E prealloc

TOPDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

GOLINT_VERSION = v2.5.0
GOLINT = $(TOPDIR)/tools-bin/golangci-lint
GOLINT_STAMP = $(TOPDIR)/tools-bin/golangci-lint-$(GOLINT_VERSION).stamp

$(GOLINT): $(GOLINT_STAMP)

$(GOLINT_STAMP):
	mkdir -p $(dir $(GOLINT))
	touch $(GOLINT_STAMP)
	GOBIN=$(dir $(GOLINT)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLINT_VERSION)

.PHONY: lint
lint: $(GOLINT)
	$(GOLINT) $(GOLINT_ARGS)

.PHONY: build
build:
	go build ./...

.PHONY: test
test:
	go test -race $(GOPKG)

.PHONY: test-cover
test-cover:
	go test -cover $(GOPKG)

.PHONY: presubmit
presubmit: test-cover lint

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  * build:          build gen-corim"
	@echo "  * test:           run unit tests"
	@echo "  * test-cover:     run unit tests and measure coverage"
	@echo "  * lint:           lint sources using default configuration and some extra checkers"
	@echo "  * presubmit:      check you are ready to push your local branch to remote"
	@echo "  * help:           print this menu"
