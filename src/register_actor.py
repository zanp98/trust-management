# scripts/register_actor.py
import json
from pathlib import Path
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, XSD
from didkit_wrap import DIDKitAPI

TRUST = Namespace("http://example.org/trust#")

# Konfiguracija poti
OWL_PATH   = Path("ontologies/pharma-trust.owl")          # obstoječa ontologija
DIDS_PATH  = Path("policies/dids.json")                   # katalog imen → DID
KEYS_DIR   = Path("keys/actors")                          # DEMO – shrani JWK
KEYS_DIR.mkdir(parents=True, exist_ok=True)

def upsert_entity_with_did(name: str, actor_type: str, did: str):
    g = Graph()
    g.parse(str(OWL_PATH), format="application/rdf+xml")

    actor_uri = URIRef(f"http://example.org/trust#{name}")
    type_uri  = URIRef(f"http://example.org/trust#{actor_type}")

    # dodaj tip in hasDID (če še ne obstaja)
    g.add((actor_uri, RDF.type, type_uri))
    g.set((actor_uri, TRUST.hasDID, Literal(did, datatype=XSD.string)))

    g.serialize(destination=str(OWL_PATH), format="application/rdf+xml")

def update_dids_catalog(name: str, did: str):
    if DIDS_PATH.exists():
        data = json.loads(DIDS_PATH.read_text(encoding="utf-8"))
    else:
        data = {}
    data[name] = did
    DIDS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

def save_jwk(name: str, jwk: str):
    path = KEYS_DIR / f"{name}.jwk"
    path.write_text(jwk, encoding="utf-8")

def register_actor(name: str, actor_type: str, did_method: str = "key"):
    """
    name: i. e. 'Pfizer', 'DHL', 'MediPlus'
    actor_type: 'Manufacturer' | 'Distributor' | 'Pharmacy' | 'Transporter' | 'RegulatoryAuthority' ...
    did_method: 'key' (privzeto) ali 'pkh' (če želiš vezavo na EVM naslov)
    """
    api = DIDKitAPI()

    if did_method == "key":
        jwk = api.generate_ed25519_key()
        did = api.key_to_did("key", jwk)
    else:
        raise ValueError("Currently only 'key' is supported.")

    upsert_entity_with_did(name, actor_type, did)
    update_dids_catalog(name, did)
    save_jwk(name, jwk)

    print(f"[OK] Actor registered: {name} :: {actor_type}")
    print(f"     DID: {did}")
    print(f"     JWK: keys/actors/{name}.jwk (DEMO)")

if __name__ == "__main__":
    # examples:
    register_actor("Pfizer", "Manufacturer")
    register_actor("DHL", "Transporter")
    register_actor("EuroLogistics", "Distributor")
    register_actor("MediPlus", "Pharmacy")
    register_actor("EMA", "RegulatoryAuthority")
    register_actor("Novartis", "RegulatoryAuthority")
