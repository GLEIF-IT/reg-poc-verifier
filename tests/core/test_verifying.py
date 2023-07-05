import falcon
from keri.app import habbing
from keri.core import coring
from keri.vdr import viring

from verifier.core import verifying, basing


def test_setup_and_endpoints():
    salt = b'0123456789abcdef'
    salter = coring.Salter(raw=salt)

    with habbing.openHby(name="verifier", salt=salter.qb64, temp=True) as hby:
        app = falcon.App()
        vdb = basing.VerifierBaser(name=hby.name, temp=True)
        reger = viring.Reger(temp=True)
        verifying.setup(app=app, hby=hby, vdb=vdb, reger=reger)

