FROM golang:latest AS cli-builder
WORKDIR /build
COPY cli/ cli/
COPY scanner/rules/ scanner/rules/
WORKDIR /build/cli
RUN go generate ./internal/rules && go build -o /cradar ./cmd/cradar

FROM python:3.12-slim
WORKDIR /app

# Install cosign
RUN apt-get update && apt-get install -y curl && \
    curl -sL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign && \
    apt-get remove -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Copy cradar CLI binary
COPY --from=cli-builder /cradar /usr/local/bin/cradar

# Install Python backend
COPY backend/pyproject.toml .
RUN pip install --no-cache-dir .
COPY backend/app/ app/

# Non-root
RUN useradd -m worker
USER worker

CMD ["taskiq", "worker", "app.workers.scan_worker:broker"]
