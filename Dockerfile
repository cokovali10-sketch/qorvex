# Qorvex multi-stage Dockerfile
# Builds Go binary, Rust sandbox, Python scanners, TypeScript dashboard

# =============================================================================
# Stage 1: Build Go binary
# =============================================================================
FROM golang:1.26-alpine AS go-builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o qorvex ./cmd/qorvex

# =============================================================================
# Stage 2: Build Rust sandbox
# =============================================================================
FROM rust:1.82-alpine AS rust-builder

RUN apk add --no-cache musl-dev

WORKDIR /app/rust

COPY rust/Cargo.toml rust/Cargo.lock* ./
COPY rust/src ./src
RUN cargo build --release

# =============================================================================
# Stage 3: Build TypeScript dashboard
# =============================================================================
FROM node:22-alpine AS ts-builder

WORKDIR /app/ts

COPY ts/package*.json ./
RUN npm ci

COPY ts/ ./
RUN npm run build

# =============================================================================
# Stage 4: Prepare Python scanners
# =============================================================================
FROM python:3.12-alpine AS py-prep

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

WORKDIR /app/python

COPY python/pyproject.toml python/README.md ./
COPY python/scanners ./scanners
COPY python/tests ./tests

# Install scanners in development mode
RUN pip install --no-cache-dir -e .

# =============================================================================
# Stage 5: Final runtime image
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    curl \
    dumb-init \
    python3 \
    py3-pip \
    git \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S qorvex-group && \
    adduser -u 1001 -S qorvex-user -G qorvex-group

WORKDIR /app

# Copy Go binary
COPY --from=go-builder /app/qorvex ./qorvex

# Copy Rust sandbox binary
COPY --from=rust-builder /app/rust/target/release/qorvex-sandbox ./qorvex-sandbox

# Copy Python scanners (installed in site-packages)
COPY --from=py-prep /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=py-prep /usr/local/bin/ /usr/local/bin/

# Copy TypeScript dashboard build
COPY --from=ts-builder /app/ts/dist/ ./assets/

# Copy configuration
COPY config/ ./config/
COPY pkg/orchestrator/rules/ ./rules/

# Create directories
RUN mkdir -p /app/data /app/logs /app/backups /app/sandbox

# Set ownership
RUN chown -R qorvex-user:qorvex-group /app

# Switch to non-root user
USER qorvex-user

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8420/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["./qorvex", "--config", "config/qorvex.yaml"]

LABEL org.opencontainers.image.title="Qorvex" \
      org.opencontainers.image.description="AI Code Verification Platform" \
      org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.authors="cokovali10-sketch" \
      org.opencontainers.image.source="https://github.com/cokovali10-sketch/qorvex" \
      org.opencontainers.image.vendor="Qorvex" \
      org.opencontainers.image.licenses="MIT"