FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w \
      -X github.com/venkatkrishna07/rift/internal/version.Version=${VERSION} \
      -X github.com/venkatkrishna07/rift/internal/version.Commit=${COMMIT} \
      -X github.com/venkatkrishna07/rift/internal/version.Date=${DATE}" \
    -o rift ./cmd/rift/

# ---- runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/rift .

VOLUME ["/data"]

EXPOSE 443/udp
EXPOSE 443/tcp
EXPOSE 80/tcp

ENTRYPOINT ["./rift", "server"]
CMD ["--db", "/data/db", "--listen", ":443", "--http", ":80"]
