from rdflib import Graph

def load_ontology(path="ontologies/trust.owl") -> Graph:
    g = Graph()
    g.parse(path, format="application/rdf+xml")
    return g
