# Cross-compilation images — selected by TARGETARCH (set automatically by buildx)
ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=registry_token \
    mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "shroudb-cratesio"\n\n[source.shroudb-cratesio]\nregistry = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\n\n[registries.shroudb-cratesio]\nindex = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\ncredential-provider = ["cargo:token"]\n\n[registries.shroudb]\nindex = "sparse+https://crates.shroudb.dev/api/v1/crates/"\ncredential-provider = ["cargo:token"]\n' > /root/.cargo/config.toml && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    CARGO_REGISTRIES_SHROUDB_CRATESIO_TOKEN="$(cat /run/secrets/registry_token)" \
    CARGO_REGISTRIES_SHROUDB_TOKEN="$(cat /run/secrets/registry_token)" \
    cargo build --release --target "$RUST_TARGET" -p shroudb-cipher-server -p shroudb-cipher-cli && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-cipher" /out/ && \
    cp "target/$RUST_TARGET/release/shroudb-cipher-cli" /out/

# --- shroudb-cipher: encryption-as-a-service engine ---
FROM alpine:3.21 AS shroudb-cipher
RUN adduser -D -u 65532 shroudb && \
    apk add --no-cache su-exec && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Cipher" \
      org.opencontainers.image.description="Encryption-as-a-service engine with keyring lifecycle management" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-cipher" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-cipher" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-cipher /shroudb-cipher
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
VOLUME /data
WORKDIR /data
EXPOSE 6599
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/shroudb-cipher"]

# --- shroudb-cipher-cli: CLI tool ---
FROM alpine:3.21 AS shroudb-cipher-cli
RUN adduser -D -u 65532 shroudb
LABEL org.opencontainers.image.title="ShrouDB Cipher CLI" \
      org.opencontainers.image.description="CLI tool for the Cipher encryption-as-a-service engine" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-cipher" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-cipher" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-cipher-cli /shroudb-cipher-cli
USER shroudb
ENTRYPOINT ["/shroudb-cipher-cli"]
