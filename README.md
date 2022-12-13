# Root CA Certificate Stores

This repository provides a PKCS#7 archive of Root CA Certificate Stores from Mozilla and Microsoft. The latest release
of this repo always contains the most recent store, and is updated automatically whenver any changes are made.

This is provided for the TLS Inspector iOS application, but can be used by anybody within the terms of the license.

*Thank you to the Mozilla team, Daniel Stenberg from curl, and Microsoft for providing the resources to make this possible!*

## About

This repository contains three components: A container image to build the certificate bundle, a github workflow to check
for and perform updates, the actual certificate bundles itself, and a metadata file.

The metadata file contains the modified date of the bundle, a SHA256 sum of the bundle file, and the number of
certificates included. The `key` property is internal to the container and should be ignored by consumers of the
bundles.

### Container

A OCI container image is included in this repository that executes a golang application to build and update the
certificate bundles.

Any changes to the certificates are comitted and included in a new release.

The bundles and metadata file are signed with an ECDSA-P256 key. The public key is included in the repository and
release. The files can be verified using OpenSSL:

```
openssl dgst -sha256 -verify signing_key.pem -signature bundle_metadata.json.sig bundle_metadata.json.sig
```

The repository is entirly self-contained and can be self-hosted or modified.

### Mozilla

To generate the Mozilla bundle, a precompiled list of certificates is downloaded from the
[curl website](https://curl.se/docs/caextract.html). The certificates are extracted and then combined into a PKCS#7
archive.

### Microsoft

To generate the Microsoft bundle, a precompiled CSV of certificates included with Windows is downloaded from the
[ccadb website](https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV). The CSV file
includes certificates that are disabled, expired, and also for purposes other than server verification. We filter these
certificates out.

Certificates are then downloaded directly from Windows Update and cached within the repository. Cached certificates are
verified for integrity.

The certificates are extracted and then combined into a PKCS#7 archive.

## License

The software that compose this repository, excluding the certificate stores and certificate data, are released under the
terms of the Mozilla Public License 2.0.
