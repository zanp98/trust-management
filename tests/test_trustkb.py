from src.trustkb.client import FusekiClient
from src.trustkb.queries import list_classes


def test_classes_query_runs():
    client = FusekiClient()
    result = client.select(list_classes(1))
    assert "results" in result
