from rdf.ontology_loader import load_ontology
from rdf.trust_reasoner import is_entity_trusted
from eth.web3_connector import connect
from eth.trust_contract import load_trust_contract, set_trust_status

# Load and reason
graph = load_ontology()
alice_uri = "http://example.org/trust#Alice"
trusted = is_entity_trusted(graph, alice_uri)

# Ethereum interaction
w3 = connect()
contract = load_trust_contract(w3, contract_address, abi)
tx = set_trust_status(contract, account, alice_eth_address, trusted)
print(f"Updated blockchain with trust={trusted}")
