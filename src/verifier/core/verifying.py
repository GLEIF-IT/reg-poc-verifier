import json

import falcon
from keri.core import coring, parsing
from keri.vdr import verifying, eventing, viring

from verifier.core import basing


def setup(app, hby, cf):
    """ Set up verifying endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        cf (Configer): Configuration loader

    """
    # TODO: Load white list of LEIs from cf here.
    vdb = basing.VerifierBaser(name=hby.name)

    reger = viring.Reger(name=hby.name, temp=hby.temp)
    tvy = eventing.Tevery(reger=reger, db=hby.db)
    vry = verifying.Verifier(hby=hby, reger=reger)

    loadEnds(app, hby, vdb, tvy, vry)


def loadEnds(app, hby, vdb, tvy, vry):
    """ Load and map endpoints to process vLEI credential verifications

    Parameters:
        app (App): Falcon app to register endpoints against
        hby (Habery): Database environment for exposed KERI AIDs
        vdb (VerifierBaser): Verifier database environment
        tvy (Tevery): transaction event log event processor
        vry (Verifier): credential verification processor

    """

    presentEnd = PresentationCollectionEndpoint(hby, vdb, tvy, vry)
    app.add_route("/presentations", presentEnd)
    presentResEnd = PresentationResourceEnd(hby, vdb)
    app.add_route("/presentations/{aid}", presentResEnd)

    requestEnd = RequestVerifierResourceEnd(hby=hby, vdb=vdb)
    app.add_route("/request/verify/{aid}", requestEnd)

    return []


class PresentationCollectionEndpoint:

    def __init__(self, hby, vdb, tvy, vry):
        self.hby = hby
        self.vdb = vdb
        self.tvy = tvy
        self.vry = vry

    def on_post(self, req, rep):
        if req.content_type not in ("application/json+cesr",):
            raise falcon.HTTPBadRequest(description=f"invalid content type={req.content_type} for VC presentation")

        ims = req.bounded_stream.read()

        parsing.Parser().parse(ims=ims,
                               kvy=self.hby.kvy,
                               tvy=self.tvy,
                               vry=self.vry)

        if not self.vry.cues:
            raise falcon.HTTPBadRequest(description="no valid credential found in body of request")

        msg = self.vry.cues.popleft()
        creder = msg["creder"]

        said = creder.said
        issuee = creder.subject["i"]

        print(f"Credential {said} presented from {issuee}")

        prefixer = coring.Prefixer(qb64=issuee)
        saider = coring.Saider(qb64=said)
        now = coring.Dater()

        self.vdb.snd.pin(keys=(saider.qb64,), val=prefixer)
        self.vdb.iss.pin(keys=(saider.qb64,), val=now)

        rep.status = falcon.HTTP_ACCEPTED


class PresentationResourceEnd:

    def __init__(self, hby, vdb):
        self.hby = hby
        self.vdb = vdb

    def on_get(self, req, rep, aid):
        """

        Parameters:
            req (Request): falcon HTTP request object
            rep (Respose): falcon HTTP response object
            aid (str): qb64 identifier to check

        Returns:

        """
        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown {aid} used to sign header")

        if said := self.vdb.acct.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        body = dict(
            aid=aid,
            said=said
        )

        rep.status = falcon.HTTP_OK
        rep.body = json.dumps(body).encode("utf-8")


class RequestVerifierResourceEnd:

    def __init__(self, hby, vdb):
        self.hby = hby
        self.vdb = vdb

    def on_post(self, req, rep, aid):
        data = req.params.get("data")
        sig = req.params.get("sig")

        if aid not in self.hby.kevers:
            raise falcon.HTTPNotFound(description=f"unknown {aid} used to sign header")

        if self.vdb.acct.get(keys=(aid,)) is None:
            raise falcon.HTTPForbidden(description=f"identifier {aid} has no valid credential for access")

        kever = self.hby.kevers[aid]
        verfers = kever.ververs
        cigar = coring.Cigar(qb64=sig)

        if not verfers[0].verify(sig=cigar.raw, ser=data.decode("utf-8")):
            raise falcon.HTTPUnauthorized(description=f"{aid} provided invalid signature on request data")

        rep.status = falcon.HTTP_ACCEPTED
