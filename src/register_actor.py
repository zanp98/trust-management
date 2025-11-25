# scripts/register_actor.py
import json
import os
from pathlib import Path

from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, XSD
from web3 import Web3

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


def _make_did_ethr(address: str, network: str | None = None) -> str:
    if not address:
        raise ValueError("ethr DID requires an Ethereum address")
    checksum = Web3.to_checksum_address(address)
    net = (network or "").strip()
    return f"did:ethr:{net}:{checksum}" if net else f"did:ethr:{checksum}"


def register_actor(
    name: str,
    actor_type: str,
    did_method: str = "key",
    eth_address: str | None = None,
    did_network: str | None = None,
):
    """
    name: i. e. 'Pfizer', 'DHL', 'MediPlus'
    actor_type: 'Manufacturer' | 'Distributor' | 'Pharmacy' | 'Transporter' | 'RegulatoryAuthority' ...
    did_method: 'key' (privzeto) ali 'ethr' (vezava na EVM naslov)
    eth_address: EVM naslov (zahtevan pri did_method='ethr')
    did_network: opcijski identifikator omrežja za did:ethr (npr. 'sepolia')
    """
    did_method = did_method.lower().strip()

    if did_method == "key":
        api = DIDKitAPI()
        jwk = api.generate_ed25519_key()
        did = api.key_to_did("key", jwk)
        save_jwk(name, jwk)
    elif did_method == "ethr":
        network = did_network or os.getenv("DID_ETHR_NETWORK", "")
        did = _make_did_ethr(eth_address, network)
        jwk = None
    else:
        raise ValueError("Supported did_method values: 'key', 'ethr'")

    upsert_entity_with_did(name, actor_type, did)
    update_dids_catalog(name, did)

    print(f"[OK] Actor registered: {name} :: {actor_type}")
    print(f"     DID: {did}")
    if did_method == "key":
        print(f"     JWK: keys/actors/{name}.jwk (DEMO)")
    elif did_method == "ethr":
        print("     (did:ethr – JWK not generated here; bind to your wallet key)")

if __name__ == "__main__":
    # examples:
    register_actor("Pfizer", "Manufacturer", did_method="key")
    register_actor("DHL", "Transporter", did_method="ethr", eth_address="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
    register_actor("EuroLogistics", "Distributor", did_method="key")
    register_actor("MediPlus", "Pharmacy", did_method="key")
    register_actor("EMA", "RegulatoryAuthority", did_method="key")
    register_actor("Novartis", "RegulatoryAuthority", did_method="key")
