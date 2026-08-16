# Multi-stage production Dockerfile for Rust Zero-Knowledge Identity API
# Stage 1: Dependency & Binary Builder
FROM rust:1.80-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build prerequisites
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests for layer caching
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && \
    echo "fn main() { println!(\"dummy\"); }" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source tree and compile release binary
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Lightweight Runtime Container
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Install CA certificates and dynamic SSL runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/sh -m appuser

# Copy compiled Rust executable
COPY --from=builder --chown=appuser:appuser /usr/src/app/target/release/zk-identity-api-rust /app/zk-identity-api-rust

USER appuser

# Application runtime environment
ENV PORT=8080 \
    RUST_LOG=zk_identity_api_rust=info,tower_http=info

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/zk-identity-api-rust", "--healthcheck"] || exit 0

CMD ["/app/zk-identity-api-rust"]
