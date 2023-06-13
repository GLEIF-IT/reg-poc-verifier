def setup(app, hby, vdb):
    pass


def loadEnds(app, hby, vdb):
    reportsEnd = ReportCollectionEnd(hby, vdb)
    app.add_route("/reports/{aid}", reportsEnd)

    reportEnd = ReportResourceEnd(hby, vdb)
    app.add_route("/reports/{aid}/{name}")


class ReportCollectionEnd:

    def __init__(self, hby, vdb):
        self.hby = hby
        self.vdb = vdb

    def on_get(self, req, rep, aid):
        pass


class ReportResourceEnd:

    def __init__(self, hby, vdb):
        self.hby = hby
        self.vdb = vdb

    def on_post(self, req, rep, aid, name):
        pass
