FROM docker.io/library/python@sha256:a71e8ff8638a437e4cd8ad80a609235af54bc04d75e1aa2832146595e31d83bc
LABEL maintainer="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.authors="Ian Spence <ian@ecnepsnai.com>"
LABEL org.opencontainers.image.source=https://github.com/tls-inspector/rootca
LABEL org.opencontainers.image.title="ian-learns-github-actions"
LABEL org.opencontainers.image.description="Generates a PKCS#7 archive of the Mozilla Root CA Certificate store and an associated metadata property list file"

RUN apk add --no-cache py3-libplist openssl

ADD build_moz_bundle.py /
VOLUME /github/workspace
WORKDIR /github/workspace

ENTRYPOINT [ "python3", "/build_moz_bundle.py" ]