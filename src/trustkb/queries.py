from .config import PHARM_NS

PREFIXES = f"""
PREFIX owl:  <http://www.w3.org/2002/07/owl#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>
PREFIX pharm: <{PHARM_NS}>
"""


def list_classes(limit: int = 100) -> str:
    return PREFIXES + f"""
    SELECT ?class WHERE {{ ?class a owl:Class }} LIMIT {limit}
    """


def manufacturers(limit: int = 100) -> str:
    return PREFIXES + f"""
    SELECT ?m WHERE {{ ?m a pharm:Manufacturer }} LIMIT {limit}
    """


def entity_triples(entity_iri: str, limit: int = 200) -> str:
    return PREFIXES + f"""
    CONSTRUCT {{ <{entity_iri}> ?p ?o }}
    WHERE     {{ <{entity_iri}> ?p ?o }} LIMIT {limit}
    """
