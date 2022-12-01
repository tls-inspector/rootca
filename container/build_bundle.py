import datetime
import os
import subprocess
import sys
import tempfile
import urllib.request
import plistlib
from pathlib import Path

wd = os.getcwd()

mozilla_bundle_path = os.path.join(wd, "moz_ca_bundle.p7b")
bundle_metadata_path = os.path.join(wd, "BundleMetadata.plist")

latest_mozilla_sha256 = urllib.request.urlopen(
    "https://curl.se/ca/cacert.pem.sha256").read().decode("utf-8").split(' ')[0].rstrip()


def make_mozilla_bundle():
    """make the mozilla root CA certificate bundle"""

    print("building mozilla root CA certificate bundle...")

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
                        mozilla_bundle_path], check=True)

    # In: Tue Oct 11 03:12:05 2022 GMT
    # Out: 2022-11-11T03:12:05Z
    actual_date = datetime.datetime.strptime(
        date, "%a %b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%dT%H:%M:%SZ")

    if os.path.exists(bundle_metadata_path):
        os.unlink(bundle_metadata_path)

    with open(bundle_metadata_path, mode='wb+') as fp:
        plistlib.dump(dict(
            mozilla_date=actual_date,
            mozilla_sha256=latest_mozilla_sha256,
        ), fp, fmt=plistlib.PlistFormat.FMT_XML)

    print("mozilla bundle created with " +
          str(len(pem_certs)) + " certificates")


def sign_file(file_name, pkey):
    """sign file_name with pkey"""

    sig_name = file_name+".sig"

    try:
        os.unlink(sig_name)
    except FileNotFoundError:
        pass

    [fd, keypath] = tempfile.mkstemp(text=True)
    with os.fdopen(fd, mode="w+", encoding="utf-8") as w:
        w.write(pkey)

    try:
        subprocess.run([
            "/usr/bin/openssl",
            "dgst",
            "-sign",
            keypath,
            "-keyform",
            "PEM",
            "-sha256",
            "-out",
            sig_name,
            "-hex",
            file_name
        ], check=True)

        print("created signature of " + file_name)
    finally:
        os.unlink(keypath)


if os.path.exists(bundle_metadata_path):
    plist = plistlib.loads(Path(bundle_metadata_path).read_bytes(),
                           fmt=plistlib.PlistFormat.FMT_XML)
    current_mozilla_sha256 = plist.get('mozilla_sha256')

    if current_mozilla_sha256 != latest_mozilla_sha256:
        make_mozilla_bundle()
else:
    make_mozilla_bundle()

signing_key = os.getenv("ROOTCA_SIGNING_KEY")
if signing_key is not None and signing_key != "":
    signing_key = signing_key.replace("\\n", "\n")

    if os.path.exists(bundle_metadata_path):
        sign_file(bundle_metadata_path, signing_key)

    if os.path.exists(mozilla_bundle_path):
        sign_file(mozilla_bundle_path, signing_key)
