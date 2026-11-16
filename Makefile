# All Go tooling runs in containers; the host needs only Docker.

GO_IMAGE := golang:1.27-alpine
GO_RUN   := docker run --rm -v "$(CURDIR)":/src -w /src \
            -v tr-proxy-gocache:/root/.cache/go-build \
            -v tr-proxy-gomod:/go/pkg/mod \
            -e CGO_ENABLED=0 $(GO_IMAGE)
COMPOSE  := docker compose -f dc/docker-compose.yaml

.PHONY: build test vet fmt tidy up down logs

build:
	docker build -t tr-proxy:dev .

test:
	$(GO_RUN) go test ./...

vet:
	$(GO_RUN) go vet ./...

fmt:
	$(GO_RUN) gofmt -l -w .

tidy:
	$(GO_RUN) go mod tidy

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f
