import json
import os
import shutil
import sys
import tempfile
import zipfile
from os.path import join, exists

from keri.core.coring import Tiers

from signify.app.clienting import SignifyClient


def sign(file, out):
    url = "http://localhost:3901"
    bran = b'0123456789abcdefghijk'
    tier = Tiers.low

    client = SignifyClient(passcode=bran, tier=tier, url=url)
    identifiers = client.identifiers()
    aid = identifiers.get("aid1")

    with tempfile.TemporaryDirectory() as tempdirname:
        z = zipfile.ZipFile(file)
        z.extractall(path=tempdirname)

        for root, dirs, files in os.walk(tempdirname):
            if "META-INF" not in dirs or 'reports' not in dirs:
                continue

            name = join(root, 'META-INF', 'reports.json')
            if not exists(name):
                manifest = dict(documentInfo=dict())
            else:
                with open(name, 'r') as f:
                    manifest = json.load(f)

            if "signatures" in manifest["documentInfo"]:
                signatures = manifest["documentInfo"]["signatures"]
            else:
                signatures = list()

            reports = join(root, 'reports')
            for entry in os.scandir(reports):
                f = open(entry.path, 'r')
                ser = f.read()
                f.close()

                sigs = identifiers.sign("aid1", ser)

                signatures.append(dict(
                    file=f"../reports/{entry.name}",
                    aid=aid["prefix"],
                    sigs=sigs
                ))

            manifest["documentInfo"]["signatures"] = signatures
            with open(name, 'w') as f:
                json.dump(manifest, f)

        shutil.make_archive(out.rstrip(".zip"), 'zip', tempdirname)


def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file),
                       os.path.relpath(os.path.join(root, file),
                                       os.path.join(path, '..')))


if __name__ == "__main__":
    sign(sys.argv[1], sys.argv[2])
