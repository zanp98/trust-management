import hashlib

import requests

from .config import FusekiConfig


def export_default_graph(cfg: FusekiConfig | None = None, accept: str = "text/turtle") -> bytes:
    cfg = cfg or FusekiConfig()
    response = requests.get(cfg.data_url, headers={"Accept": accept})
    response.raise_for_status()
    return response.content


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_default_graph(cfg: FusekiConfig | None = None) -> str:
    data = export_default_graph(cfg)
    return sha256_bytes(data)
