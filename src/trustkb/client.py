from SPARQLWrapper import BASIC, JSON, POST, SPARQLWrapper

from .config import FusekiConfig


class FusekiClient:
    def __init__(self, cfg: FusekiConfig | None = None):
        self.cfg = cfg or FusekiConfig()

    def select(self, query: str) -> dict:
        sparql = SPARQLWrapper(self.cfg.query_url)
        sparql.setQuery(query)
        sparql.setReturnFormat(JSON)
        return sparql.query().convert()

    def update(self, update_query: str) -> None:
        sparql = SPARQLWrapper(self.cfg.update_url)
        sparql.setMethod(POST)
        if self.cfg.user:
            sparql.setHTTPAuth(BASIC)
            sparql.setCredentials(self.cfg.user, self.cfg.passwd)
        sparql.setQuery(update_query)
        sparql.query()
