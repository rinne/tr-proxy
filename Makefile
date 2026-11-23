# All Go tooling runs in containers; the host needs only Docker.

GO_IMAGE := golang:1.27-alpine
GO_RUN   := docker run --rm -v "$(CURDIR)":/src -w /src \
            -v tr-proxy-gocache:/root/.cache/go-build \
            -v tr-proxy-gomod:/go/pkg/mod \
            -e CGO_ENABLED=0 $(GO_IMAGE)
# The race detector needs cgo, which the alpine image has no C compiler for.
RACE_IMAGE := golang:1.27
RACE_RUN := docker run --rm -v "$(CURDIR)":/src -w /src \
            -v tr-proxy-gocache-race:/root/.cache/go-build \
            -v tr-proxy-gomod:/go/pkg/mod \
            -e CGO_ENABLED=1 -e GOFLAGS=-buildvcs=false $(RACE_IMAGE)
COMPOSE  := docker compose -f dc/docker-compose.yaml

.PHONY: build test race vet fmt check vulncheck smoke tidy up down logs

build:
	docker build --pull -t tr-proxy:local .

test:
	$(GO_RUN) go test ./...

race:
	$(RACE_RUN) go test -race ./...

vet:
	$(GO_RUN) go vet ./...

fmt:
	$(GO_RUN) gofmt -l -w .

# What CI and the release script run before the tests: fails if a file is
# not gofmt-formatted or vet complains.
check:
	$(GO_RUN) sh -c 'out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not formatted (run: make fmt):"; echo "$$out"; exit 1; fi; go vet ./...'

# Known vulnerabilities in the code paths tr-proxy uses (Go standard
# library and modules), from the Go vulnerability database.
vulncheck:
	$(GO_RUN) go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# End-to-end test of the built image.
smoke:
	tests/smoke.sh

tidy:
	$(GO_RUN) go mod tidy

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f
