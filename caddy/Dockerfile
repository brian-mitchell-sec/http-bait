# Custom Caddy with JA4 client-TLS fingerprinting (+ ja4h HTTP fingerprint).
# caddy-ja4 needs Go >=1.25, newer than the stock caddy builder, so build with golang:1.25.
FROM golang:1.25 AS builder
WORKDIR /b
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
# Pinned to exact commits (supply-chain hygiene — a future upstream change can't alter
# what runs on the TLS proxy without a deliberate version bump here).
RUN xcaddy build \
    --with github.com/matt-/caddy-ja4@v0.0.0-20251115234144-2e6b958122db \
    --with github.com/lum8rjack/caddy-ja4h@v0.0.0-20260111160035-4ad5f179c702
FROM caddy:2.8-alpine
COPY --from=builder /b/caddy /usr/bin/caddy
