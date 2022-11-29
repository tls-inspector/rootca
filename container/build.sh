#!/bin/bash
set -e

VERSION=${1:?Version required}
REVISION=$(git rev-parse HEAD)
DATETIME=$(date --rfc-3339=seconds)

podman build \
    --squash \
    --no-cache \
    --label "org.opencontainers.image.created=${DATETIME}" \
    --label "org.opencontainers.image.version=${VERSION}" \
    --label "org.opencontainers.image.revision=${REVISION}" \
    -t ghcr.io/tls-inspector/rootca:${VERSION} \
    -t ghcr.io/tls-inspector/rootca:latest \
    .
podman push ghcr.io/tls-inspector/rootca:${VERSION}
podman push ghcr.io/tls-inspector/rootca:latest
