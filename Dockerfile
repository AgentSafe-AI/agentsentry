# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

ARG VERSION=dev

# Install git for `git describe` in build scripts
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache module downloads separately from source changes
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Build both binaries with optimised flags: no CGO, stripped symbols
RUN CGO_ENABLED=0 go build \
      -ldflags "-X main.version=${VERSION} -s -w" \
      -o /out/tooltrust-scanner \
      ./cmd/tooltrust-scanner/

RUN CGO_ENABLED=0 go build \
      -ldflags "-X main.version=${VERSION} -s -w" \
      -o /out/tooltrust-mcp \
      ./cmd/tooltrust-mcp/

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
FROM scratch

# Copy TLS root certificates (needed for outbound HTTPS in the scanner)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy compiled binaries
COPY --from=builder /out/tooltrust-scanner     /usr/local/bin/tooltrust-scanner
COPY --from=builder /out/tooltrust-mcp /usr/local/bin/tooltrust-mcp

# Default: run the MCP server so registries like Glama can inspect it.
ENTRYPOINT ["/usr/local/bin/tooltrust-mcp"]

# Metadata labels (OCI standard)
LABEL org.opencontainers.image.title="ToolTrust Scanner"
LABEL org.opencontainers.image.description="AI Agent Tool Security Scanner"
LABEL org.opencontainers.image.source="https://github.com/AgentSafe-AI/tooltrust-scanner"
LABEL org.opencontainers.image.licenses="MIT"
