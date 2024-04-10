FROM docker.io/library/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
# https://hub.docker.com/_/alpine/tags
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