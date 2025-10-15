from dataclasses import dataclass
import os

from dotenv import load_dotenv

load_dotenv()


@dataclass
class FusekiConfig:
    base_url: str = os.getenv("FUSEKI_BASE_URL", "http://localhost:3030")
    dataset: str = os.getenv("FUSEKI_DATASET", "trustkb")
    user: str = os.getenv("FUSEKI_USER", "")
    passwd: str = os.getenv("FUSEKI_PASS", "")

    @property
    def query_url(self) -> str:
        return f"{self.base_url}/{self.dataset}/query"

    @property
    def update_url(self) -> str:
        return f"{self.base_url}/{self.dataset}/update"

    @property
    def data_url(self) -> str:
        return f"{self.base_url}/{self.dataset}/data"


PHARM_NS = os.getenv(
    "PHARM_NS",
    "http://www.semanticweb.org/zanp/ontologies/2024/10/trust-management-system#",
)
