FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy all source files
COPY . .

# Build the Qorvex binary
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o qorvex ./cmd/qorvex

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl dumb-init

# Create non-root user for security
RUN addgroup -g 1001 -S qorvex-group && \
    adduser -u 1001 -S qorvex-user -G qorvex-group

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/qorvex ./qorvex

# Copy configuration files
COPY --from=builder /app/config/ ./config/
COPY --from=builder /app/pkg/orchestrator/rules/ ./rules/

# Copy static assets if any
COPY --from=builder /app/ts/dist/ ./assets/

# Create directories
RUN mkdir -p /app/data /app/logs /app/backups

# Set ownership
RUN chown -R qorvex-user:qorvex-group /app

# Switch to non-root user
USER qorvex-user

# Expose port
EXPOSE 8420

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8420/health || exit 1

# Default command
ENTRYPOINT ["dumb-init", "--"]
CMD ["./qorvex", "--config", "config/qorvex.yaml"]

# Labels for the image
LABEL org.opencontainers.image.title="Qorvex" \
      org.opencontainers.image.description="AI Code Verification Platform" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.authors="cokovali10-sketch" \
      org.opencontainers.image.source="https://github.com/cokovali10-sketch/qorvex" \
      org.opencontainers.image.vendor="Qorvex" \
      org.opencontainers.image.licenses="MIT"