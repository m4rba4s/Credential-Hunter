# Multi-stage build for optimized container
FROM rust:1.75-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY ech-core/ ./ech-core/
COPY ech-simd/ ./ech-simd/
COPY ech-cli/ ./ech-cli/
COPY ech-agent/ ./ech-agent/
COPY ech-plugin/ ./ech-plugin/

# Build in release mode
RUN cargo build --release --bin ech --bin ech-daemon

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ech

# Copy binaries
COPY --from=builder /app/target/release/ech /usr/local/bin/
COPY --from=builder /app/target/release/ech-daemon /usr/local/bin/

# Create directories
RUN mkdir -p /var/lib/ech /var/log/ech /etc/ech \
    && chown -R ech:ech /var/lib/ech /var/log/ech /etc/ech

# Switch to non-root user
USER ech

# Default command
CMD ["ech-daemon"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["ech", "info"]

# Labels
LABEL org.opencontainers.image.title="Enterprise Credential Hunter"
LABEL org.opencontainers.image.description="Advanced credential hunting and DFIR system"
LABEL org.opencontainers.image.vendor="Enterprise Security"
LABEL org.opencontainers.image.licenses="Commercial"