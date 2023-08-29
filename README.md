# Root CA Certificate Stores

This repository provides collections of Root CA Certificate Stores from Apple, Google, Microsoft, and Mozilla.
The latest release of this repo always contains the most recent store, and is updated automatically whenever any changes
are made.

This is provided for the TLS Inspector iOS application, but can be used by anybody within the terms of the license. The
repository is entirely self-contained and can be self-hosted or modified.

## About

This repository contains the following components: An update utility that builds the certificate bundles, a container
and github workflow using that utility to check for and perform updates, and the actual certificate bundles and metadata.

The certificate bundles are packaged as PKCS#7 archives with the certificates included in the Certificate/CRL section,
and a text file with the PEM-encoded certificates.

The primary metadata file contains the modified date of the bundle, a checksums of the bundle files, and the number of
certificates included. The key property is internal to the container and should be ignored by consumers of the
bundles. Additionally, a comma-separated-value list of all certificates included in the bundles is provided for
reference, but should not be programmatically relied upon.

For information on the update utility, see updater/README.md.

### Verification

Bundles & Metadata are signed by a ECDSA-P256 key and have an accompaning signature file.
The sining public key is included in the repo and in each release.

You can verify the signature of the files using OpenSSL (using `bundle_metadata.json` as an example):

```bash
openssl dgst -sha256 -verify signing_key.pem -signature bundle_metadata.json.sig bundle_metadata.json
```

## Bundles

### Apple

To generate the Apple bundle, certificates are downloaded directly from [Apple's OSS GitHub Repo](https://github.com/apple-oss-distributions/security_certificates).

### Google

The Google bundle is based on the [Chromium source code](https://github.com/chromium/chromium/blob/main/net/data/ssl/chrome_root_store/root_store.certs)
, which contains certificates participating in the [Chrome Root Program](https://g.co/chrome/root-policy).

### Microsoft

The Microsoft bundle is based on [Microsoft Trusted Root program](https://learn.microsoft.com/en-us/security/trusted-root/participants-list)
, utilizing [Windows Subject Trust Lists](https://github.com/tls-inspector/authrootstl) downloaded directly from Windows
Update. Only certificates that are trusted, valid for Server Authentication, and not expired are included.

### Mozilla

To generate the Mozilla bundle, a prepared list of certificates extracted from Firefox is downloaded from the [curl website](https://curl.se/docs/caextract.html).

### TLS Inspector

The TLS Inspector bundle is a collection of certificate that are trusted equally by all other vendors. For example, a
certificate that Microsoft trusts that Google does not is not included in this bundle.

## API Usage

You can use the GitHub API to progmatically query for and download these bundles

1. Query for the latest tag

    ```
    HTTP GET https://api.github.com/repos/tls-inspector/rootca/tags
    ```

    The first object in the response is always the latest tag. Store the `name` value for that tag.

2. Download assets

    ```
    HTTP GET https://raw.githubusercontent.com/tls-inspector/rootca/$tag_name/bundles/$asset_file_name
    ```

    Populate `$tag_name` with the name of the tag from above and `$asset_file_name` with the name of the bundle asset
    to download. Don't include the path.

    The above URL may return a redirect, so ensure your HTTP client is set to follow them.

    **Always download the accompiying signature file for any downloaded assets and verify them against the public key in the repo!**

## License

The software that compose this repository, **excluding** the certificate stores and certificate data, are released under the
terms of the Mozilla Public License 2.0.

*Apple*, *Google*, *Chromium*, *Chrome*, *Microsoft*, *Windows*, *Mozilla*, and *Firefox* are all registered trademarks
belonging to their respective owners. This package is not affiliated with or endorsed by any third party, including but
not limited to the afformentioned entities.

Root certificates, such as those included in this software, are typically considered public data and are not encumbered
by licenses. However, this authors of this software are not liable for any violations you may make by using this software.

The export/import and/or use of strong cryptography software, providing cryptography hooks, or even just communicating
technical details about cryptography software is illegal in some parts of the world. You are responsible for knowing and
adhering to the laws and requirements of your locality. The authors of this software are not liable for any violations
you make by using this software.
