# Root CA Certificate Stores

This repository provides collections of Root CA Certificate Stores from Apple, Google, Microsoft, and Mozilla.
The latest release of this repo always contains the most recent store, and is updated automatically whenever any changes
are made.

This is provided for the TLS Inspector iOS application, but can be used by anybody within the terms of the license. The
repository is entirely self-contained and can be self-hosted or modified.

## About

This repository contains the following components: An update utility that builds the certificate bundles, a container,
and a GitHub workflow using that utility to check for and perform updates, and the actual certificate bundles and metadata.

The certificate bundles are packaged as PKCS#7 archives with the certificates included in the Certificate/CRL section,
and a text file with the PEM-encoded certificates.

The primary metadata file contains the modified date of the bundle, a checksums of the bundle files, and the number of
certificates included. The key property is internal to the container and should be ignored by consumers of the
bundles. Additionally, a comma-separated-value list of all certificates included in the bundles is provided for
reference, but should not be programmatically relied upon.

For information on the update utility, see updater/README.md.

### Verification

Bundles & Metadata are signed by an ECDSA-P256 key and have an accompanying signature file.
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

TLS Inspector provides an API to pragmatically query for and download certificate bundles.

The base of the API is `https://api.tlsinspector.com`.

All requests must have a valid and somewhat identifiable user-agent header. We reject requests that
use a default user agent header such as `curl/...` or `python-requests/...`.

This API is provided "as-is" and with no guarantees of availability or up-time. We reserve the right
to revoke your access to the API at our discretion.

### Get Latest Bundle Name

**Request:**

```
GET /rootca/latest
```

**Response:**

<details><summary>Expand sample response</summary>

```json
{"version":"bundle_20241001"}
```

</details>

### Get Bundle Metadata

**Request:**

```
GET /rootca/metadata/<version>
```

Where `<version>` is either "latest" or a specific bundle version name

**Response:**

<details><summary>Expand sample response</summary>

```json
{
  "mozilla": {
    "date": "2024-09-24T03:12:04Z",
    "key": "189d3cf6d103185fba06d76c1af915263c6d42225481a1759e853b33ac857540",
    "bundles": {
      "mozilla_ca_bundle.p7b": {
        "sha1": "26D68DA317362C95E9247DA2682881EA0A5DB9AA",
        "sha256": "860241DE2497A9C1FBAB89FC7DA4E72057CA6BB1808CF97F0E40ED874854FC84",
        "sha512": "33DAE15848361022B53F8F45909BF344A0069EF6ECB087D7279F95A8D5FA1A4A5C786595BBA1CA2AFA83A17FA35D73AD87BC39B121CEC91F279924211CD29A3C"
      },
      "mozilla_ca_bundle.pem": {
        "sha1": "CEC93AB707461E9C603B5FD3E4A31A389839D9C1",
        "sha256": "990FF5205FC2D63D8ED8878D75B3A6D2038B339593E1AC945114005423B7BB0B",
        "sha512": "E449EE310D9BD4220BDF21AC2875877A0B083DC5C367AFB64B47B0F79F7062D091A87E81D59E43831BF3402023E431DA1A26505581DCC5AD47251EF4EEED75A6"
      }
    },
    "num_certs": 151
  },
  "microsoft": {
    "date": "2024-05-29T18:29:14Z",
    "key": "8EFBC21559EF8B1BCF526800D8070BAAD42474CE7198E26FA771DBB41A76B1D8",
    "bundles": {
      "microsoft_ca_bundle.p7b": {
        "sha1": "B0A5B9863BA7B03D1CF4CB1AA08AF1665D4F6083",
        "sha256": "5F898CF2ECF8A76E118579B7FC6EDB74EDD900A3714BC6D5D94834183D882AD2",
        "sha512": "A74B465A60EB333F404523667E6D969CFDD9741A4006B7448020C224CDF4570A7E95F7B005E04DFBF261A27E4FE8EB0D1309BB9B5E318284E8AA04D2AB0FD752"
      },
      "microsoft_ca_bundle.pem": {
        "sha1": "1B6F6F2398FAB9E8282E936A73CDD7CDC7C84E48",
        "sha256": "00514CA800495D3BA43A057A8E3E524445B3E6C77DAF98931EB4D6CA6DCF0A80",
        "sha512": "3B4B461B6B566A8B25D0C185AF444CCBD62BA7B9E6FBE55095704BA3E16C6D7323C8BFA4FFD56FBE94FC2657D489CA66ECD4CE1006654D0A57E67E7A90E8B788"
      }
    },
    "num_certs": 246
  },
  "google": {
    "date": "2024-05-30T15:58:06Z",
    "key": "cb239fbd1505c9af5ca8ee8b1338ddafebb313a7",
    "bundles": {
      "google_ca_bundle.p7b": {
        "sha1": "9DA3354D3AD8CB49F4EB4FD464D0D69D13E876A7",
        "sha256": "658229855FB52E6C8F8E08E672406720C8ED59B27B1A24F85EFFCA7B65179295",
        "sha512": "A951EAF67122CE7C98DCBCA6797B0200BD4234C3EDAD92B5CD40FD940CB5A4C12E61E639C5FCE0A0BA6BA4326D16F8321C3956E089F0426E4445771C92AE3A7A"
      },
      "google_ca_bundle.pem": {
        "sha1": "DC384A087559C50EF2A4A5D6D4698C6103F5AD8B",
        "sha256": "7C53781E3CBE3A92BC54446430F3640735787A1ACB8CE9E69B6722AB081ACFB9",
        "sha512": "EA58F9C818B616569B699FE259F801A7B07D5EF08CE4D08E7B867E0321C8DF3D75054FBE54C92ADE4BA6AE81AF3322B137A30C6CE5FB2A188F665D55D22A77F4"
      }
    },
    "num_certs": 135
  },
  "apple": {
    "date": "2024-09-24T17:44:43Z",
    "key": "9c061d71693f4b9ccdddea087ff0428755604bf0",
    "bundles": {
      "apple_ca_bundle.p7b": {
        "sha1": "F14804A4FBB644321C5AAEA8F4C445F540A0A4CC",
        "sha256": "9991AF551E8CE48F849630DC934A4F431CFE61059B766C14773D9480D40EDC91",
        "sha512": "8398D32323BC2A318D0FBEC7E97833B34C119B54F24F515608BC8C4E6631A8A34922488FB5334C88EA1C5DAFFD61D7CFC5F7EC40A2B1FE884DF6F519FC80A61B"
      },
      "apple_ca_bundle.pem": {
        "sha1": "7614DD1CBD006D9DBE1F670924A18F0452995D3D",
        "sha256": "0266922E2A7FCA20F0493B23F45BF1202391E51E401AEC6CB45DC57ECE4CE976",
        "sha512": "4135240B826A00BB1202529D75F97B0938B16BAE38E58D12C88BC336BE4745D8BB2169E34D63E4EDB46244A218E0C7E82ACB4AACD83B65FF3B507C1B0FFB9BF9"
      }
    },
    "num_certs": 154
  },
  "tls_inspector": {
    "date": "2024-10-01T18:39:11Z",
    "key": "379D3D92AD598A20E26C087C34C243E87C6215B25A65391ABFA92826D0E4A6EC",
    "bundles": {
      "tlsinspector_ca_bundle.p7b": {
        "sha1": "781DED01A80C85DB200B18AE08CA87F74F0ED3CD",
        "sha256": "9F344E6DA29BA6CF6B83A77386D3B59A8157D1C03ACB9C78A8F3569F28AD7EE4",
        "sha512": "44FC44CFF159D0A0B63971A18B93101F029146C443351CA9D60B881B8719FCECB107F4D1FB52D6C33487EB7BB3AAF804B45725D9C376C926DA6E6E26974CD48F"
      },
      "tlsinspector_ca_bundle.pem": {
        "sha1": "0BF93005601DF9CAE9CFE51B38C0A585263E1B59",
        "sha256": "7626B4B7C72ABEBD19C975D862A04A8F3E7673E4EACA6383CF751F1362665A06",
        "sha512": "0334DCB39D42770CAE293845EE37E05FAD11DBB324D9A28EA5E63939D6E4CCA725FC61F0EDF15E2AD6D6862DE04CDE7D20034FDE2D612F7120D95CF737D5BD3C"
      }
    },
    "num_certs": 117
  }
}
```

</details>

### Get Bundle Asset

**Request:**

```
GET /rootca/asset/<version>/<file name>
```

Where `<version>` is either "latest" or a specific bundle version name, and `<file name>` is the name of an assets file. Only files that are attached to [releases](https://github.com/tls-inspector/rootca/releases/latest) can be downloaded.

**Response:**

The response to this request will be the binary contest of the asset file. Visiting this URL in a browser will trigger a download.

## License

The software that compose this repository, **excluding** the certificate stores and certificate data, are released under the
terms of the Mozilla Public License 2.0.

*Apple*, *Google*, *Chromium*, *Chrome*, *Microsoft*, *Windows*, *Mozilla*, and *Firefox* are all registered trademarks
belonging to their respective owners. This package is not affiliated with or endorsed by any third party, including but
not limited to the aforementioned entities.

Root certificates, such as those included in this software, are typically considered public data and are not encumbered
by licenses. However, this authors of this software are not liable for any violations you may make by using this software.

The export/import and/or use of strong cryptography software, providing cryptography hooks, or even just communicating
technical details about cryptography software is illegal in some parts of the world. You are responsible for knowing and
adhering to the laws and requirements of your locality. The authors of this software are not liable for any violations
you make by using this software.
