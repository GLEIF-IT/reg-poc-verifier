import json
from collections import namedtuple
from dataclasses import asdict

import falcon
from keri.core import coring

from verifier.core.basing import ReportStats


# SAID field labels
Reportage = namedtuple("Reportage", "accepted verified failed")

ReportStatus = Reportage(accepted="accepted", verified="verified", failed="failed")


def setup(app, hby, vdb):
    filer = Filer(vdb=vdb)

    loadEnds(app, hby, vdb, filer)


def loadEnds(app, hby, vdb, filer):
    reportEnd = ReportResourceEnd(hby, vdb, filer)
    app.add_route("/reports/{aid}/{dig}", reportEnd)


class Filer:

    def __init__(self, vdb):
        self.vdb = vdb

    def create(self, aid, dig, typ, stream):
        self.vdb.delTopVal(db=self.vdb.imgs, key=dig.encode("utf-8"))
        stats = ReportStats(
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
        self.vdb.stats.put(keys=(dig,), val=stats)

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

        self.filer.create(aid=aid, dig=dig, typ=req.content_type, stream=req.bounded_stream)
        rep.status = falcon.HTTP_202
