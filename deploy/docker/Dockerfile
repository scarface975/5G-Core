# Multi-stage build of the C network functions. UNVERIFIED on this project's host: the Docker daemon was not available when
# this file was written (see docs/update.md); `docker build` it before relying on it.
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config libssl-dev libnghttp2-dev libuv1-dev libpq-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /out -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/g5c \
    && cmake --build /out -j"$(nproc)" \
    && ctest --test-dir /out --output-on-failure \
    && cmake --install /out

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libssl3t64 libnghttp2-14 libuv1t64 libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/g5c --create-home g5c
COPY --from=build /opt/g5c/bin/ /usr/local/bin/
COPY deploy/docker/g5c-entrypoint /usr/local/bin/g5c-entrypoint
USER 10001
# The NF and its config are chosen at run time: `docker run g5c udm /etc/g5c/udm.yaml`
ENTRYPOINT ["/usr/local/bin/g5c-entrypoint"]
