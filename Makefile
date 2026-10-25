# Releases use the reviewed vendored SIEM clients. Override GOWORK explicitly only for
# coordinated development with a sibling integrations checkout.
export GOWORK ?= off

.PHONY: help lint test deps-check vulncheck hook hook-verify

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

lint: ## gofmt + go vet (also for macOS, where the hook runs)
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "run gofmt -w"; exit 1)
	go vet ./...
	GOOS=darwin go vet ./...

test: ## Run the tests with the race detector
	go test -race -count=1 ./...

deps-check: ## Fail if any package builds against a module outside github.com/Altiward
	@mods=$$(go list -deps -test -f '{{with .Module}}{{.Path}}{{end}}' ./...) || exit 1; \
	out=$$(echo "$$mods" | sort -u | grep -v -e '^github.com/Altiward/' -e '^$$'); \
	test -z "$$out" || (echo "third-party modules aren't allowed:"; echo "$$out"; exit 1)

vulncheck: ## Check the code and the Go toolchain against Go's vulnerability database
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

hook: ## Build the hook package, ad hoc signed (packaging/build.sh; VERSION=… to set one)
	packaging/build.sh

hook-verify: ## Check the hook package build.sh made
	packaging/verify.sh
