FROM docker.io/library/python@sha256:a71e8ff8638a437e4cd8ad80a609235af54bc04d75e1aa2832146595e31d83bc
LABEL maintainer="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.authors="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.source=https://github.com/tls-inspector/rootca
LABEL org.opencontainers.image.title="rootca"
LABEL org.opencontainers.image.description="Generates a PKCS#7 archive of the Root CA Certificate Stores"

RUN apk add --no-cache openssl

ENV ROOTCA_SIGNING_PRIVATE_KEY=""
ENV ROOTCA_SIGNING_PUBLIC_KEY=""

ADD rootca /
RUN chmod +x /rootca
VOLUME /github/workspace
WORKDIR /github/workspace/bundles

ENTRYPOINT [ "/rootca" ]