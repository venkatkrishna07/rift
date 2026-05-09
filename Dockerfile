# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.25
ARG TAGS=
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

FROM golang:${GO_VERSION}-alpine AS builder
ARG TAGS
ARG VERSION
ARG COMMIT
ARG DATE
RUN apk add --no-cache git
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -trimpath \
      -tags "${TAGS}" \
      -ldflags="-s -w \
        -X github.com/venkatkrishna07/rift/internal/version.Version=${VERSION} \
        -X github.com/venkatkrishna07/rift/internal/version.Commit=${COMMIT} \
        -X github.com/venkatkrishna07/rift/internal/version.Date=${DATE}" \
      -o /out/rift ./cmd/rift/

# ---- runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S rift && adduser -S -G rift -H rift && \
    mkdir -p /data && chown -R rift:rift /data
COPY --from=builder /out/rift /usr/local/bin/rift

LABEL org.opencontainers.image.source="https://github.com/venkatkrishna07/rift"
LABEL org.opencontainers.image.description="rift — self-hosted QUIC tunnel"
LABEL org.opencontainers.image.licenses="MIT"

# QUIC + HTTPS share 443; 80 is for ACME HTTP-01.
# Map TCP tunnel range at runtime: -p 10000-10010:10000-10010.
EXPOSE 443/udp 443/tcp 80/tcp

VOLUME ["/data"]
USER rift
ENTRYPOINT ["/usr/local/bin/rift"]
# No default CMD — pass `server ...` or `client ...` explicitly.
