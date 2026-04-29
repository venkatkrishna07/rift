module github.com/venkatkrishna07/rift

go 1.25.1

require (
	github.com/dgraph-io/badger/v4 v4.9.1
	github.com/quic-go/quic-go v0.59.0
	github.com/venkatkrishnas/caddy-mcp v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.50.0
	golang.org/x/sync v0.20.0
	golang.org/x/time v0.15.0
)

replace github.com/venkatkrishnas/caddy-mcp => ../caddy-mcp

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgraph-io/ristretto/v2 v2.4.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
