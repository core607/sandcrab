# syntax=docker/dockerfile:1
FROM rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS helper
COPY crates/sandcrab-launch/bwrap /bwrap-recipe
RUN sh /bwrap-recipe/build.sh /bundle

FROM --platform=$BUILDPLATFORM rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS source
WORKDIR /source
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

FROM source AS check
RUN rustup component add rustfmt clippy \
    && host_arch="$(uname -m)" \
    && if [ "$host_arch" = x86_64 ]; then export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld; else export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld; fi \
    && cargo fmt --all --check \
    && cargo clippy --locked --all-targets --target x86_64-unknown-linux-musl -- -D warnings \
    && cargo clippy --locked --all-targets --target aarch64-unknown-linux-musl -- -D warnings \
    && cargo test --locked --target "${host_arch}-unknown-linux-musl"

FROM source AS binary
ARG TARGETARCH
RUN host_arch="$(uname -m)" \
    && if [ "$host_arch" = x86_64 ]; then export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld; else export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld; fi \
    && case "${TARGETARCH:-amd64}" in \
      amd64) rust_target=x86_64-unknown-linux-musl ;; \
      arm64) rust_target=aarch64-unknown-linux-musl ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH:-}" >&2; exit 1 ;; \
    esac \
    && cargo build --locked --release --target "$rust_target" --bin sandcrab \
    && mkdir /notices /out \
    && cp "/source/target/$rust_target/release/sandcrab" /out/sandcrab \
    && cargo metadata --locked --offline --format-version 1 --filter-platform "$rust_target" > /notices/dependencies.json \
    && cp "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html" /notices/rust-library-copyright.html

FROM helper AS package
ARG TARGETARCH
COPY --from=binary /out/sandcrab /bundle/sandcrab
COPY --from=binary /usr/local/cargo/registry/src/ /usr/local/cargo/registry/src/
COPY --from=binary /notices/dependencies.json /recipe/dependencies.json
COPY --from=binary /notices/rust-library-copyright.html /bundle/rust-library-copyright.html
COPY crates/sandcrab/install/__main__.py /recipe/__main__.py
COPY THREAT-MODEL.md /bundle/THREAT-MODEL.md
COPY LICENSE /bundle/LICENSE
COPY scripts/package.py /recipe/package.py
COPY scripts/third_party_notices.py /recipe/third_party_notices.py
RUN case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64 ;; \
      arm64) arch=aarch64 ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH:-}" >&2; exit 1 ;; \
    esac \
    && python3 /recipe/third_party_notices.py /recipe/dependencies.json /bundle/THIRD-PARTY-NOTICES.txt \
    && python3 /recipe/package.py /bundle /recipe/__main__.py "$arch"

FROM scratch AS release
COPY --from=package /bundle/ /
