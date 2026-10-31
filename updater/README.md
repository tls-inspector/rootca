The rootca update tool is a golang application that can be used to maintain a directory of certificate bundles.

### Requirements
 - OpenSSL 3.x
 - `cabextract`
 - `tar`
 - `aea` (⚠️ **macOS only!**)
 - `aa` (⚠️ **macOS only!**)

A macOS device is required to update the Apple bundle, as the bundle is provided in a Apple-proprietary encrypted format
that required macOS-only tools to decrypt and extract.

We're aware this is a significant limitation and are looking into fixing it, but we can not provide a timeline yet.

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
 ROOTCA_SIGNING_PRIVATE_KEY   Specify the private key PEM contents. Escape newlines with double backslaces.
 GITHUB_ACCESS_TOKEN   Specify a Github access token used for read-only API requests.
```
