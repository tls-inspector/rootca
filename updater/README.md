The rootca update tool is a golang application that can be used to maintain a directory of certificate bundles.

### Requirements
 - OpenSSL 3.x
 - cabextract
 - tar

### Usage

```
Usage ./rootca [options] [workdir]

Workdir: The directory where the bundles will be saved. Defaults to "bundles". Will create the directory if it does not exist.

Options:
 --public-key-path   Optionally specify a path to a PEM-encoded signing public key.
 --private-key-path  Optionally specify a path to a PEM-encoded signing private key.
 --openssl-path      Optionally specify the path to openssl executable. Defaults to looking in $PATH.
 --cabextract-path   Optionally specify the path to cabextract executable. Defaults to looking in $PATH.
 --force-update      Forcefully trigger an update of all bundles. By default bundles will only be updated if changes are detected.

Environment Variables:
 ROOTCA_SIGNING_PUBLIC_KEY   Specify the public key PEM contents. Escape newlines with double backslashes.
 ROOTCA_SIGNING_PRIVATE_KEY  Specify the private key PEM contents. Escape newlines with double backslaces.
```

### Container

The `ghcr.io/tls-inspector/rootca` container image is provided mostly for use within Github workflows. **You do not need to use the container**.