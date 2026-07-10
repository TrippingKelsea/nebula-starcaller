# syntax=docker/dockerfile:1.7

# ---------- Nebula binaries ----------
# Fetch nebula + nebula-cert for the platforms we bundle.
# Version pinned; bump ARG NEBULA_VERSION when upstream releases.
ARG NEBULA_VERSION=v1.10.3

FROM alpine:3.20 AS nebula-fetch
ARG NEBULA_VERSION
RUN apk add --no-cache curl tar unzip

# Runtime binaries for supported bundle targets.
WORKDIR /out
RUN set -eux; \
    fetch_tar() { \
        os=$1; arch=$2; url="https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-${os}-${arch}.tar.gz"; \
        mkdir -p /out/binaries/${os}-${arch}; \
        curl -fsSL "$url" | tar -xz -C /out/binaries/${os}-${arch}; \
    }; \
    fetch_zip() { \
        os=$1; arch=$2; url="https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-${os}-${arch}.zip"; \
        mkdir -p /tmp/z && cd /tmp/z && rm -rf ./* ; \
        curl -fsSL -o out.zip "$url"; \
        unzip -o out.zip -d /out/binaries/${os}-${arch}; \
    }; \
    fetch_tar linux amd64; \
    fetch_tar linux arm64; \
    fetch_tar darwin arm64 || echo "darwin-arm64 not available in this release"; \
    fetch_zip windows amd64 || echo "windows-amd64 not available"

# Place nebula-cert (linux/amd64) on the container PATH — this is the one
# the server will shell out to for CA and signing operations.
RUN cp /out/binaries/linux-amd64/nebula-cert /out/nebula-cert && chmod +x /out/nebula-cert

# ---------- Build the Go binary ----------
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/starcaller ./cmd/starcaller

# ---------- Runtime image ----------
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 65532 starcaller && adduser -D -u 65532 -G starcaller starcaller

COPY --from=nebula-fetch /out/nebula-cert /usr/local/bin/nebula-cert
COPY --from=nebula-fetch /out/binaries /opt/starcaller/binaries
COPY --from=build /out/starcaller /usr/local/bin/starcaller

ENV STARCALLER_DATA_DIR=/var/lib/starcaller \
    STARCALLER_NEBULA_CERT=/usr/local/bin/nebula-cert \
    STARCALLER_BINARIES_DIR=/opt/starcaller/binaries \
    STARCALLER_LISTEN=0.0.0.0:8080 \
    STARCALLER_RP_ID=localhost \
    STARCALLER_RP_ORIGINS=http://localhost:8080

RUN mkdir -p /var/lib/starcaller && chown -R starcaller:starcaller /var/lib/starcaller
USER starcaller
EXPOSE 8080
VOLUME ["/var/lib/starcaller"]
ENTRYPOINT ["/usr/local/bin/starcaller"]
