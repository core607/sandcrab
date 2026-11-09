FROM debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash python3 mount passwd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sandcrab
COPY --chmod=0755 sandcrab bwrap ./
COPY --chmod=0644 bwrap-notices.txt bwrap-source.tar.xz LICENSE THREAT-MODEL.md ./
RUN ln -s /opt/sandcrab/sandcrab /usr/local/bin/sandcrab
ENTRYPOINT ["/opt/sandcrab/sandcrab"]
CMD ["serve", "--container"]
