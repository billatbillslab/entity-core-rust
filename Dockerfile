# syntax=docker/dockerfile:1.7
#
# Entity Core Rust — container build.
#
# Stages:
#   toolchain  Rust + wasm32 target + clippy/rustfmt. No source. Used as the
#              base for dev/CI services that bind-mount the repo at /work.
#   builder    toolchain + repo source, produces the release `entity` binary.
#   runtime    Debian slim carrying just the binary. Default target.
#
# The Rust version is pinned by rust-toolchain.toml; keep the base image tag
# in sync with that file.

FROM rust:1.94.1-bookworm AS toolchain
WORKDIR /work
RUN rustup target add wasm32-unknown-unknown \
 && rustup component add clippy rustfmt

FROM toolchain AS builder
COPY . .
RUN cargo build --release -p entity-cli \
 && install -Dm755 target/release/entity /out/entity

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/entity /usr/local/bin/entity
ENTRYPOINT ["entity"]
