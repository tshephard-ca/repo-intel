FROM rust:1-bookworm AS builder

WORKDIR /app/generated
COPY generated/Cargo.toml generated/Cargo.lock ./
RUN mkdir -p src/backing \
  && printf 'fn main() {}\n' > src/main.rs \
  && cargo build --release \
  && rm -rf src

COPY generated/src ./src
RUN rm -f target/release/metadatacollectionfacade-facade \
    target/release/deps/metadatacollectionfacade_facade* \
  && rm -rf target/release/.fingerprint/metadatacollectionfacade-facade-* \
  && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /app frontplane

COPY --from=builder /app/generated/target/release/metadatacollectionfacade-facade /usr/local/bin/metadata-collection-facade

ENV METADATA_COLLECTION_DATA_DIR=/data/metadata-collection

RUN mkdir -p /data/metadata-collection \
  && chown -R frontplane:frontplane /data /app

USER frontplane
WORKDIR /app
VOLUME ["/data/metadata-collection"]
EXPOSE 18080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/metadata-collection-facade", "--healthcheck", "127.0.0.1:18080"]

CMD ["/usr/local/bin/metadata-collection-facade", "--host", "0.0.0.0", "--port", "18080"]
