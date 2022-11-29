# Mozilla Root CA Certificate Store

This repository provides a PKCS#7 archive of the Mozilla Root CA Certificate Store. The latest release of this repo
always contains the most recent store, and is updated automatically whenver any changes are made.

This is provided for the TLS Inspector iOS application, but can be used by anybody within the terms of the license.

*Thank you to the Mozilla team and Daniel Stenberg from curl for providing the resources to make this possible!*

## About

This repository contains three components: A container image to build the certificate bundle, a github workflow to check
for and perform updates, and the actual certificate bundle itself.

The container image includes a python script that downloads the latest certificate export from the
[curl website](https://curl.se/docs/caextract.html) and then prepares a PKCS#7 archive. It also generates an Apple
Property List file containing the date and shasum. This is used to determine if updates are required the next time the
script runs.

The Github workflow executes the container image hosted on Github Container Registry and, if any changes to the bundle
were made, will tag and create a new release.

The repository is entirly self-contained and can be self-hosted or modified.

## License

The Mozilla Root CA Certiicate Store is provided by Mozilla as part of the Firefox web browser, which is published
under the terms of the Mozilla Public License 2.0.

Additionally, the certificates are extracted and provided by the curl project, also released under the Mozilla Public
License 2.0.

The scripts that compose this repository, excluding the certificate store, are released under the terms of the Mozilla
Public License 2.0.
