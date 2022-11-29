import datetime
import os
import subprocess
import sys
import tempfile
import urllib.request
import plistlib
from pathlib import Path

wd = os.getcwd()

latest_sha_sum = urllib.request.urlopen(
    "https://curl.se/ca/cacert.pem.sha256").read().decode("utf-8").split(' ')[0].rstrip()

if os.path.exists(os.path.join(wd, "BundleMetadata.plist")):
    plist = plistlib.loads(Path("BundleMetadata.plist").read_bytes(),
                           fmt=plistlib.PlistFormat.FMT_XML)
    current_sha_sum = plist['sha256']

    if current_sha_sum == latest_sha_sum:
        print("mozilla ca bundle is up to date")
        sys.exit(0)

print("warning: mozilla ca bundle updated")

moz_bundle = urllib.request.urlopen("https://curl.se/ca/cacert.pem").read()

pem_certs = []
pem = b''
in_cert = False
date = ''
for line in moz_bundle.split(b'\n'):
    if line == b'-----BEGIN CERTIFICATE-----':
        in_cert = True

    if in_cert:
        pem += line
        pem += b'\n'
        if line == b'-----END CERTIFICATE-----':
            pem_certs.append(pem)
            pem = b''
            in_cert = False
    else:
        if b'## Certificate data from Mozilla as of:' in line:
            date = line.decode(
                "utf-8").replace('## Certificate data from Mozilla as of: ', '')

if len(pem_certs) == 0:
    print("No certificates!")
    sys.exit(1)

with tempfile.TemporaryDirectory() as tmpdirname:
    os.chdir(tmpdirname)

    params = [
        "/usr/bin/openssl",
        "crl2pkcs7",
        "-nocrl"
    ]

    i = 0
    for cert in pem_certs:
        file_name = "cert" + str(i) + ".cer"
        with open(file_name, 'wb') as cert_file:
            cert_file.write(cert)

        params.append("-certfile")
        params.append(file_name)
        i += 1

    params.append("-out")
    params.append("moz_ca_bundle.p7b")

    subprocess.run(params, check=True)
    subprocess.run(["mv", "moz_ca_bundle.p7b",
                   os.path.join(wd, "moz_ca_bundle.p7b")], check=True)

# In: Tue Oct 11 03:12:05 2022 GMT
# Out: 2022-11-11T03:12:05Z
actual_date = datetime.datetime.strptime(
    date, "%a %b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%dT%H:%M:%SZ")

if os.path.exists(os.path.join(wd, "BundleMetadata.plist")):
    os.unlink(os.path.join(wd, "BundleMetadata.plist"))

with open(os.path.join(wd, "BundleMetadata.plist"), mode='wb+') as fp:
    plistlib.dump(dict(
        date=actual_date,
        sha256=latest_sha_sum,
    ), fp, fmt=plistlib.PlistFormat.FMT_XML)
