from .config import PHARM_NS
from .queries import PREFIXES


def insert_manufacturer(local_name: str, trust_score: float | None = None) -> str:
    node = f"<{PHARM_NS}{local_name}>"
    score_fragment = ""
    if trust_score is not None:
        score_fragment = f' ; pharm:hasTrustScore "{trust_score}"^^xsd:decimal'
    return PREFIXES + f"""
    INSERT DATA {{
      {node} a pharm:Manufacturer{score_fragment} .
    }}
    """


def link_trusted_partner(src_local: str, dst_local: str) -> str:
    src = f"<{PHARM_NS}{src_local}>"
    dst = f"<{PHARM_NS}{dst_local}>"
    return PREFIXES + f"""
    INSERT DATA {{
      {src} pharm:trustedPartner {dst} .
    }}
    """


def delete_entity(local_name: str) -> str:
    node = f"<{PHARM_NS}{local_name}>"
    return PREFIXES + f"""
    DELETE WHERE {{ {node} ?p ?o . }}
    """
