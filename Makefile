.PHONY: build vet tidy lint clean dev-server dev-client

BINARY  := rift
MODULE  := github.com/venkatkrishna07/rift

# Version is injected by CI via git tags.
# Local builds always produce "dev" unless you override manually:
#   make build VERSION=v1.0.0 COMMIT=abc1234 DATE=2026-04-15
VERSION ?= dev
COMMIT  ?= none
DATE    ?= unknown

LDFLAGS := -ldflags "\
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT)   \
  -X $(MODULE)/internal/version.Date=$(DATE)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/rift/

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
