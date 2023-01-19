# Root CA Certificate Stores

This repository provides a PKCS#7 archive of Root CA Certificate Stores from Apple, Google, Microsoft, and Mozilla.
The latest release of this repo always contains the most recent store, and is updated automatically whenever any changes
are made.

This is provided for the TLS Inspector iOS application, but can be used by anybody within the terms of the license.

## About

This repository contains the following components: A container image to build the certificate bundle, a github workflow
to check for and perform updates, the actual certificate bundles itself, and metadata files.

The certificate bundles are packaged as PKCS#7 archives, with the certificates included in the Certificate/CRL section.
The bundles do not utilize PKCS#7 signatures or encryption.

The primary metadata file contains the modified date of the bundle, a SHA256 sum of the bundle file, and the number of
certificates included. The `key` property is internal to the container and should be ignored by consumers of the
bundles. Additionally, a comma-separated-value list of all certificates included in the bundles is provided for
reference, but should not be programmatically relied upon.

### Container

A OCI container image is included in this repository that executes a golang application to build and update the
certificate bundles.

Any changes to the certificates are committed and included in a new release.

The bundles and metadata file are signed with an ECDSA-P256 key. The public key is included in the repository and
release. The files can be verified using OpenSSL:

```
openssl dgst -sha256 -verify signing_key.pem -signature bundle_metadata.json.sig bundle_metadata.json.sig
```

The repository is entirely self-contained and can be self-hosted or modified.

### Apple

To generate the Apple bundle, a precompiled list of certificates is downloaded from the
[Apple Support website](https://support.apple.com/en-ca/HT213464). The certificates are downloaded directly from crt.sh
and then combined into a PKCS#7 archive.

### Google

To generate the Google bundle, a precompiles list of certificates is downloaded from the
[Chromium source mirror on Github](https://github.com/chromium/chromium/blob/main/net/data/ssl/chrome_root_store/root_store.certs).
The certificates are extracted and then combined into a PKCS#7 archive.

### Microsoft

To generate the Microsoft bundle, a precompiled CSV of certificates included with Windows is downloaded from the
[ccadb website](https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV). The CSV file
includes certificates that are disabled, expired, and also for purposes other than server verification. We filter these
certificates out.

Certificates are then downloaded directly from Windows Update and verified for integrity.

The certificates are extracted and then combined into a PKCS#7 archive.

### Mozilla

To generate the Mozilla bundle, a precompiled list of certificates is downloaded from the
[curl website](https://curl.se/docs/caextract.html). The certificates are extracted and then combined into a PKCS#7
archive.

### TLS Inspector

The TLS Inspector bundle is a collection of certificates that are present in every vendor bundle. Vendors may choose to
trust or not trust specific certificates at their own discretion, for example Apple trusts their own root CA whereas no
other vendors do.

## License

The software that compose this repository, excluding the certificate stores and certificate data, are released under the
terms of the Mozilla Public License 2.0.
