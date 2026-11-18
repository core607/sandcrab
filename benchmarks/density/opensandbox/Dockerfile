FROM debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS workload
RUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates git python3 ripgrep && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace

FROM workload AS client
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/client && /opt/client/bin/pip install --disable-pip-version-check --no-cache-dir opensandbox==1.2.1
COPY benchmarks/density/workload.py benchmarks/density/protocol.py benchmarks/density/protocol.json benchmarks/density/opensandbox/client.py /opt/measure/
ENTRYPOINT ["/opt/client/bin/python", "-u", "/opt/measure/client.py"]

FROM workload AS machine
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus docker.io iptables python3-venv && rm -rf /var/lib/apt/lists/* \
    && systemctl mask docker.service docker.socket containerd.service \
    && python3 -m venv /opt/download && /opt/download/bin/pip wheel --disable-pip-version-check --wheel-dir /opt/wheels opensandbox-server==1.2.1 \
    && rm -rf /opt/download /root/.cache/pip
ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
