# -*- encoding: utf-8 -*-
"""
vLEI Verification Servcie
verfier.core.handling module

EXN Message handling
"""
import datetime

from hio.base import doing
from keri.app import agenting
from keri.core import coring
from keri.help import helping


EBA_DOCUMENT_SUBMITTER_ROLE = "EBA Document Submitter"


class Schema:
    ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"


class Authorizer(doing.DoDoer):
    """
    Authorizer is responsible for comminucating the receipt and successful verification
    of credential presentation and revocation messages from external third parties via
    web hook API calls.


    """

    TimeoutAuth = 600

    def __init__(self, hby, hab, vdb, reger, leis):
        """

        Create a communicator capable of persistent processing of messages and performing
        web hook calls.

        Parameters:
            hby (Habery): identifier database environment
            hab (Hab): identifier environment of this Authorizer.  Used to sign hook calls
            vdb (VerifierBaser): communication escrow database environment
            reger (Reger): credential registry and database

        """
        self.hby = hby
        self.hab = hab
        self.vdb = vdb
        self.reger = reger
        self.leis = leis

        self.witq = agenting.WitnessInquisitor(hby=hby)

        self.clients = dict()

        super(Authorizer, self).__init__(doers=[self.witq, doing.doify(self.escrowDo), doing.doify(self.monitorDo)])

    def processPresentations(self):

        for (said,), dater in self.vdb.iss.getItemIter():
            # cancel presentations that have been around longer than timeout
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(seconds=self.TimeoutAuth):
                self.vdb.iss.rem(keys=(said,))
                print(f"removing {said}, it expired")
                continue

            if self.reger.saved.get(keys=(said,)) is not None:
                self.vdb.iss.rem(keys=(said,))
                creder = self.reger.creds.get(keys=(said,))
                match creder.schema:
                    case Schema.ECR_SCHEMA_SAID:
                        self.processEcr(creder)
                    case _:
                        print(f"invalid credential presentation, schema {creder.schema}")

    def processEcr(self, creder):
        if creder.subject["i"] not in self.hby.kevers:
            return

        kever = self.hby.kevers[creder.subject["i"]]

        LEI = creder.subject["LEI"]
        if LEI not in self.leis:
            return

        role = creder.subject["engagementContextRole"]

        if role not in (EBA_DOCUMENT_SUBMITTER_ROLE,):
            return

        self.vdb.accts.pin(keys=(kever.pre,), val=creder.saider)

    def processRevocations(self):

        for (said,), dater in self.vdb.rev.getItemIter():

            # cancel revocations that have been around longer than timeout
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(seconds=self.TimeoutAuth):
                self.vdb.rev.rem(keys=(said,))
                continue

            creder = self.reger.ccrd.get(keys=(said,))
            if creder is None:  # received revocation before credential.  probably an error but let it timeout
                continue

            regk = creder.status
            state = self.reger.tevers[regk].vcState(creder.said)
            if state is None:  # received revocation before status.  probably an error but let it timeout
                continue

            elif state.ked['et'] in (coring.Ilks.iss, coring.Ilks.bis):  # haven't received revocation event yet
                continue

            elif state.ked['et'] in (coring.Ilks.rev, coring.Ilks.brv):  # revoked
                self.vdb.rev.rem(keys=(said,))
                self.vdb.revk.pin(keys=(said, dater.qb64), val=creder)

    def escrowDo(self, tymth, tock=1.0):
        """ Process escrows of comms pipeline

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchor
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            try:
                self.processEscrows()
            except Exception as e:
                print(e)

            yield 0.5

    def monitorDo(self, tymth, tock=1.0):
        """ Process active account AIDs to update on rotations

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            for (said,), (prefixer, seqner) in self.vdb.accts.getItemIter():
                self.witq.query(src=self.hab.pre, pre=prefixer.qb64)

                kever = self.hby.kevers[prefixer.qb64]
                if kever.sner.num > seqner.num:
                    print("Identifier rotation detected")
                    creder = self.reger.creds.get(keys=(said,))
                    match creder.schema:
                        case Schema.ECR_SCHEMA_SAID:
                            user = creder.subject["LEI"]
                        case _:
                            continue

                    self.vdb.accts.pin(keys=(creder.said,), val=(kever.prefixer, kever.sner))
                yield 1.0

            yield 5.0

    def processEscrows(self):
        """
        Process credental presentation pipelines

        """
        self.processPresentations()
        self.processRevocations()
