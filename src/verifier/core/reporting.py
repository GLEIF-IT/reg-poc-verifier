import json
import os
import tempfile
import zipfile
from collections import namedtuple
from dataclasses import asdict

import falcon
from hio.base import doing
from keri import kering
from keri.core import coring

from verifier.core.basing import ReportStats


# Report Statuses.
Reportage = namedtuple("Reportage", "accepted verified failed")

ReportStatus = Reportage(accepted="accepted", verified="verified", failed="failed")


def setup(app, hby, vdb):
    filer = Filer(vdb=vdb)
    rverfer = ReportVerifier(hby=hby, vdb=vdb, filer=filer)

    loadEnds(app, hby, vdb, filer)

    return [rverfer]


def loadEnds(app, hby, vdb, filer):
    reportEnd = ReportResourceEnd(hby, vdb, filer)
    app.add_route("/reports/{aid}/{dig}", reportEnd)


class Filer:

    def __init__(self, vdb):
        self.vdb = vdb

    def create(self, aid, dig, filename, typ, stream):
        self.vdb.delTopVal(db=self.vdb.imgs, key=dig.encode("utf-8"))
        stats = ReportStats(
            submitter=aid,
            filename=filename,
            status=ReportStatus.accepted,
            contentType=typ,
            size=0
        )

        idx = 0
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            key = f"{dig}.{idx}".encode("utf-8")
            self.vdb.setVal(db=self.vdb.imgs, key=key, val=chunk)
            idx += 1
            stats.size += len(chunk)

        diger = coring.Diger(qb64=dig)
        self.vdb.rpts.add(keys=(aid,), val=diger)
        self.vdb.stts.add(keys=(stats.status,), val=diger)
        self.vdb.stats.pin(keys=(dig,), val=stats)

    def get(self, dig):
        """ Return report stats for given report. """
        if (stats := self.vdb.stats.get(keys=(dig,))) is None:
            return None

        return stats

    def set(self, dig, status):
        """ Update status of previously created report """
        if (stats := self.vdb.stats.get(keys=(dig,))) is None:
            raise ValueError(f"report {dig} not found")

        stats.status = status

        self.vdb.stats.pin(dig, stats)

    def getData(self, dig):
        """ Generator that yields image data in 4k chunks for identifier

        Parameters:
            dig (str): qb64 digest of report to load

        """
        idx = 0
        while True:
            key = f"{dig}.{idx}".encode("utf-8")
            chunk = self.vdb.getVal(db=self.vdb.imgs, key=key)
            if not chunk:
                break
            yield bytes(chunk)
            idx += 1

    def getAcceptedIter(self):
        for diger in self.vdb.stts.getIter(keys=(ReportStatus.accepted, )):
            yield diger

    def update(self, diger, status, msg=None):
        if (stats := self.vdb.stats.get(keys=(diger.qb64,))) is None:
            return False

        self.vdb.stts.rem(keys=(stats.status,), val=diger)

        stats.status = status
        if msg is not None:
            stats.message = msg

        self.vdb.stts.add(keys=(stats.status,), val=diger)
        self.vdb.stats.pin(keys=(diger.qb64,), val=stats)


class ReportResourceEnd:

    def __init__(self, hby, vdb, filer):
        self.hby = hby
        self.vdb = vdb
        self.filer = filer

    def on_get(self, req, rep, aid, dig):
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown AID: {aid}")

        if self.vdb.accts.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        stats = self.filer.get(dig)
        if stats is None:
            raise falcon.HTTPNotFound(description=f"report {dig} not found")

        rep.status = falcon.HTTP_200
        rep.data = json.dumps(asdict(stats)).encode("utf-8")

    def on_post(self, req, rep, aid, dig):
        """  Report Resource POST Method

        Parameters:
            req: falcon.Request HTTP request
            rep: falcon.Response HTTP response
            aid: qb64 identifier prefix of uploader
            dig: qb64 Digest of report contents

        ---
         summary: Uploads an image to associate with identfier.
         description: Uploads an image to associate with identfier.
         tags:
            - Contacts
         parameters:
           - in: path
             name: prefix
             schema:
                type: string
             description: identifier prefix to associate image to
         requestBody:
             required: true
             content:
                image/jpg:
                  schema:
                    type: string
                    format: binary
                image/png:
                  schema:
                    type: string
                    format: binary
         responses:
           200:
              description: Image successfully uploaded

        """
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown AID: {aid}")

        if self.vdb.accts.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        form = req.get_media()
        upload = False
        for part in form:
            if part.name == "upload":
                self.filer.create(aid=aid, dig=dig, filename=part.secure_filename, typ=part.content_type,
                                  stream=part.stream)
                upload = True

        if not upload:
            raise falcon.HTTPBadRequest(description=f"content type must be multipart/form-data with an upload"
                                                    f" file")

        rep.status = falcon.HTTP_202


class ReportVerifier(doing.Doer):

    def __init__(self, hby, vdb, filer, **kwargs):
        self.hby = hby
        self.vdb = vdb
        self.filer = filer

        super(ReportVerifier, self).__init__(**kwargs)

    def recur(self, tyme):
        for diger in self.filer.getAcceptedIter():
            try:
                stats = self.vdb.stats.get(keys=(diger.qb64,))
                print(f"Processing {stats.filename}:\n "
                      f"\tType={stats.contentType}\n"
                      f"\tSize={stats.size}")
                with tempfile.TemporaryFile("w+b") as tf:

                    for chunk in self.filer.getData(diger.qb64):
                        tf.write(chunk)

                    tf.seek(0)

                    with tempfile.TemporaryDirectory() as tempdirname:
                        z = zipfile.ZipFile(tf)
                        z.extractall(path=tempdirname)

                        files = []
                        manifest = None
                        for root, dirs, files in os.walk(tempdirname):
                            if "META-INF" not in dirs or 'reports' not in dirs:
                                continue

                            metaDir = os.path.join(root, 'META-INF')
                            name = os.path.join(root, 'META-INF', 'reports.json')
                            if not os.path.exists(name):
                                continue

                            f = open(name, 'r')
                            manifest = json.load(f)
                            if "documentInfo" not in manifest:
                                raise kering.ValidationError("Invalid manifest file in report package, missing "
                                                             "'documentInfo")
                            reportsDir = os.path.join(root, 'reports')
                            files = os.listdir(reportsDir)

                        if manifest is None:
                            raise kering.ValidationError("No manifest in file, invalid signed report package")

                        docInfo = manifest["documentInfo"]

                        if "signatures" not in docInfo:
                            raise kering.ValidationError("No signatures found in manifest file")

                        signatures = docInfo["signatures"]
                        signed = []
                        for signature in signatures:
                            try:
                                file = signature["file"]
                                fullpath = os.path.normpath(os.path.join(metaDir, file))
                                signed.append(os.path.basename(fullpath))
                                f = open(fullpath, 'r')
                                ser = f.read()
                                f.close()

                                aid = signature["aid"]

                                # First check to ensure signature if from submitter, otherwise skip
                                if aid != stats.submitter:
                                    continue

                                # Now ensure we know who this AID is and that we have their key state
                                if aid not in self.hby.kevers:
                                    raise kering.ValidationError(f"signature from unknown AID {aid}")

                                kever = self.hby.kevers[aid]
                                sigers = [coring.Siger(qb64=sig) for sig in signature["sigs"]]
                                if len(sigers) == 0:
                                    raise kering.ValidationError(f"missing signatures on {file}")

                                for siger in sigers:
                                    siger.verfer = kever.verfers[siger.index]  # assign verfer
                                    if not siger.verfer.verify(siger.raw, ser):  # verify each sig
                                        raise kering.ValidationError(f"signature {siger.index} invalid for {file}")

                            except KeyError as e:
                                raise kering.ValidationError(f"Invalid signature in manifest signature list"
                                                             f"missing '{e.args[0]}'")
                            except OSError:
                                raise kering.ValidationError(f"signature element={signature} point to invalid file")

                        diff = set(files) - set(signed)
                        if len(diff) == 0:
                            msg = f"All {len(files)} files in report package have been signed by " \
                                  f"submitter ({stats.submitter})."
                            self.filer.update(diger, ReportStatus.verified, msg)
                            print(msg)
                        else:
                            msg = f"{len(diff)} files from report package not signed {diff}, {signed}"
                            self.filer.update(diger, ReportStatus.failed, msg)
                            print(msg)

            except (kering.ValidationError, zipfile.BadZipFile) as e:
                self.filer.update(diger, ReportStatus.failed, e.args[0])
                print(e.args[0])






