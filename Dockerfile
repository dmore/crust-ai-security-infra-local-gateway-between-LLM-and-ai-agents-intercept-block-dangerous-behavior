FROM golang:1.26.1-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Use the install script in non-interactive mode:
# --local .        build from copied source (skip git clone)
# --prefix         install to /usr/local/bin
# --data-dir       pre-create data directory
# --no-font        no Nerd Font in containers
# --no-completion  no shell completion in containers
ENV CI=true
RUN bash install.sh --local . --prefix /usr/local/bin --data-dir /tmp/crust-data \
    --no-font --no-completion --no-tui

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 crust && \
    mkdir -p /home/crust/.crust/rules.d && chown -R crust:crust /home/crust/.crust

COPY --from=builder /usr/local/bin/crust /usr/local/bin/crust

USER crust
WORKDIR /home/crust

EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1
ENTRYPOINT ["crust", "start", "--foreground", "--auto", "--listen-address", "0.0.0.0"]
