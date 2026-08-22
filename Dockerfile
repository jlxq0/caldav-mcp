# syntax=docker/dockerfile:1.7

# Multi-stage build → distroless runtime. Final image ~20-25 MiB.
# caldav-mcp has no C build dependencies and no bundled database. It is a
# stateless CalDAV MCP server built with pure Rust and rustls.

ARG RUST_VERSION=1.93
# Digest pinned to rust:1.93-bookworm (OCI index). Update via Renovate.
FROM rust:${RUST_VERSION}-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

ARG BUILD_REVISION=unknown
ENV CALDAV_MCP_BUILD_REVISION=${BUILD_REVISION}

WORKDIR /build

# Cache dependencies separately from source: copy manifest first, build a
# stub, then copy real source. `cargo build` only re-runs the slow dependency
# compile if Cargo.toml / Cargo.lock change.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("dep stub"); }' > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src target/release/deps/caldav_mcp* target/release/caldav-mcp*

COPY src ./src
RUN cargo build --release --locked

# Distroless runtime: no shell, no apt. `cc` variant ships glibc + ca-certs,
# which we need for HTTPS to Logto (JWKS) and Stalwart (CalDAV).
# linux/amd64 manifest, pinned independently of the multi-architecture index.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9a5775272c79c226db4d6762d3b5a2caffb2b9a59dcbe5ce8dc8879c9c404115

ARG BUILD_VERSION=0.1.1
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
LABEL org.opencontainers.image.title="caldav-mcp" \
      org.opencontainers.image.description="Streamable-HTTP MCP server for Stalwart CalDAV" \
      org.opencontainers.image.url="https://github.com/jlxq0/caldav-mcp" \
      org.opencontainers.image.source="https://github.com/jlxq0/caldav-mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_CREATED}"

WORKDIR /app
COPY --from=builder /build/target/release/caldav-mcp /app/caldav-mcp

# Non-root by default (distroless `nonroot`, UID 65532).
USER nonroot:nonroot

EXPOSE 3000
ENTRYPOINT ["/app/caldav-mcp"]
