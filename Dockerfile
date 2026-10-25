# ---- build -----------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# ---- runtime ---------------------------------------------------------------
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
	&& adduser -D -u 10001 gateway

WORKDIR /app
COPY --from=build /out/gateway /usr/local/bin/gateway

RUN mkdir -p /data && chown gateway:gateway /data
USER gateway

ENV GATEWAY_LISTEN=:8080 \
    GATEWAY_DB_PATH=/data/gateway.db \
    GATEWAY_LOG_JSON=true

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
	CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/gateway"]
