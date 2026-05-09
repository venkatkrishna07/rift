.PHONY: build test vet tidy lint clean dev-server dev-client docker docker-mcp

BINARY  := rift
MODULE  := github.com/venkatkrishna07/rift

# Version is injected by CI via git tags.
# Override manually if needed:
#   make build VERSION=v1.0.0 DATE=2026-04-15
VERSION ?= dev
DATE    ?= $(shell date -u +%Y-%m-%d)

LDFLAGS := -ldflags "\
  -X $(MODULE)/cmd/rift/internal/version.Version=$(VERSION) \
  -X $(MODULE)/cmd/rift/internal/version.Date=$(DATE)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/rift/

test:
	go test ./... -timeout 120s -race

vet:
	go vet ./...

tidy:
	go mod tidy

lint: vet
	@which staticcheck >/dev/null 2>&1 \
		&& staticcheck ./... \
		|| echo "staticcheck not installed — run: go install honnef.co/go/tools/cmd/staticcheck@latest"

clean:
	rm -f $(BINARY)

dev-server:
	go run ./cmd/rift/ server --dev --listen :4443 --db /tmp/rift-dev-server

dev-client:
	go run ./cmd/rift/ client --server localhost:4443 --insecure \
		--expose 3000:http --db /tmp/rift-dev-client

# Build container image. Override IMAGE / TAGS for custom builds.
#   make docker IMAGE=ghcr.io/you/rift:v1.0.0
#   make docker-mcp                              # builds with -tags mcp
IMAGE ?= rift:$(VERSION)

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE) .

docker-mcp:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg DATE=$(DATE) \
		--build-arg TAGS=mcp \
		-t $(IMAGE)-mcp .
