FROM docker.io/library/alpine@sha256:93d5a28ff72d288d69b5997b8ba47396d2cbb62a72b5d87cd3351094b5d578a0
LABEL maintainer="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.authors="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.source=https://github.com/tls-inspector/rootca
LABEL org.opencontainers.image.title="rootca"
LABEL org.opencontainers.image.description="Root CA Certificate Bundles"

RUN apk add --no-cache openssl cabextract tar

ENV ROOTCA_SIGNING_PRIVATE_KEY=""
ENV ROOTCA_SIGNING_PUBLIC_KEY=""
ENV GITHUB_ACCESS_TOKEN=""

ADD rootca /
RUN chmod +x /rootca
VOLUME /github/workspace

ENTRYPOINT [ "/rootca" ]