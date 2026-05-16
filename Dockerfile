FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        file \
        iproute2 \
        procps \
        strace \
        timeout \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash analyst

COPY container/entrypoint.sh /usr/local/bin/sandbox-entrypoint
RUN chmod +x /usr/local/bin/sandbox-entrypoint

USER analyst
WORKDIR /home/analyst

ENTRYPOINT ["/usr/local/bin/sandbox-entrypoint"]
