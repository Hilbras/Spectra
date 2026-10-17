# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------------
FROM rust:1-bookworm AS builder

WORKDIR /app

# Dependencies are copied first so the dependency layer is cached independently
# of source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY apps/ apps/

# The workspace no longer links against OpenSSL: reqwest uses rustls, matching
# sqlx's `runtime-tokio-rustls`. No libssl-dev is required.
RUN cargo build --release --bin spectra-api --bin spectra-worker --bin spectra \
    && strip target/release/spectra-api target/release/spectra-worker target/release/spectra

# --- Runtime stage -----------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Required so the API can resolve a self-reference; the app itself refuses to
# start without these.
ENV SPECTRA_JWT_SECRET="" \
    SPECTRA_ADMIN_PASSWORD=""

RUN useradd --system --create-home --home-dir /home/spectra --shell /usr/sbin/nologin spectra

COPY --from=builder /app/target/release/spectra-api /usr/local/bin/
COPY --from=builder /app/target/release/spectra-worker /usr/local/bin/
COPY --from=builder /app/target/release/spectra /usr/local/bin/

# The dashboard is served by spectra-api. It was previously omitted, so the
# compile-time `CARGO_MANIFEST_DIR` path resolved to a directory that does not
# exist in the image and `GET /` returned 404.
COPY --from=builder /app/apps/api/static/ /opt/spectra/static/
ENV SPECTRA_STATIC_DIR=/opt/spectra/static

USER spectra
WORKDIR /home/spectra

# Must match `Config::default().server.port` (8080). It previously said 3000
# while the server bound 8080 and compose published 3000:3000, so the container
# was unreachable.
EXPOSE 8080

# The process exits non-zero with a clear message if SPECTRA_JWT_SECRET is
# unset, if it is shorter than 32 bytes, or if no admin account can be
# established. Those are intentional: this is a security tool, and starting
# with a guessable signing key or a default admin password is worse than not
# starting.
ENTRYPOINT ["spectra-api"]
