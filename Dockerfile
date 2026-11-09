# syntax=docker/dockerfile:1
FROM rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS helper
COPY crates/sandcrab-launch/bwrap /bwrap-recipe
RUN sh /bwrap-recipe/build.sh /bundle

FROM rust:1.99.1-alpine@sha256:557a94c82b485a14b569120e00867267108c734efe33f10cc31ca0cd5dd1eca9 AS source
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

FROM source AS check
RUN rustup component add rustfmt clippy \
    && cargo fmt --all --check \
    && cargo clippy --locked --all-targets --target x86_64-unknown-linux-musl -- -D warnings \
    && cargo test --locked --target x86_64-unknown-linux-musl

FROM source AS binary
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --bin sandcrab
RUN mkdir /notices \
    && cargo metadata --locked --offline --format-version 1 --filter-platform x86_64-unknown-linux-musl > /notices/dependencies.json \
    && cp "$(rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html" /notices/rust-library-copyright.html

FROM helper AS package
COPY --from=binary /source/target/x86_64-unknown-linux-musl/release/sandcrab /bundle/sandcrab
COPY --from=binary /usr/local/cargo/registry/src/ /usr/local/cargo/registry/src/
COPY --from=binary /notices/dependencies.json /recipe/dependencies.json
COPY --from=binary /notices/rust-library-copyright.html /bundle/rust-library-copyright.html
COPY crates/sandcrab/install/__main__.py /recipe/__main__.py
COPY THREAT-MODEL.md /bundle/THREAT-MODEL.md
COPY LICENSE /bundle/LICENSE
COPY scripts/package.py /recipe/package.py
COPY scripts/third_party_notices.py /recipe/third_party_notices.py
RUN python3 /recipe/third_party_notices.py /recipe/dependencies.json /bundle/THIRD-PARTY-NOTICES.txt \
    && python3 /recipe/package.py /bundle /recipe/__main__.py

FROM scratch AS release
COPY --from=package /bundle/ /
