FROM rust:1.93-bookworm AS builder
WORKDIR /app

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY openapi.yaml ./
COPY src ./src
COPY migrations ./migrations
COPY static ./static
RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/faktoro-sync-server /usr/local/bin/faktoro-sync-server
COPY --from=builder /app/migrations ./migrations

ENV RUST_LOG=info
EXPOSE 8080
CMD ["faktoro-sync-server"]
