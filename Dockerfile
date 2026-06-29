# ============================================================
# SlowQL - Next-generation SQL static analyzer
# Multi-stage build for minimal production image
# ============================================================

FROM rust:1.82-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

# ============================================================
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/slowql /usr/local/bin/slowql

RUN adduser -D -u 1000 slowql
USER slowql

WORKDIR /src

ENTRYPOINT ["slowql"]
CMD ["--help"]
