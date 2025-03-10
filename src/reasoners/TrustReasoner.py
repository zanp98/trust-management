from rdflib import Graph, Namespace, RDF
from web3 import Web3

# Load the trust ontology
g = Graph()
g.parse("../ontologies/trust.owl", format="xml")

# Define namespace
TRUST = Namespace("http://example.org/trust#")

def is_trusted(person_uri):
    """
    Determines if a person is trusted based on the ontology.
    A person is trusted if they have a VerifiedCredential.
    """
    query = f"""
    ASK WHERE {{
        <{person_uri}> <{TRUST.hasCredential}> <{TRUST.VerifiedCredential}> .
    }}
    """
    result = g.query(query)
    return bool(result.askAnswer)

# Example entity
alice_uri = "http://example.org/trust#Alice"

# Check if Alice is trusted
alice_trust_status = is_trusted(alice_uri)
print(f"Is Alice trusted? {alice_trust_status}")

# Connect to Ethereum blockchain
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))  # Local testnet

# Load smart contract
contract_address = "0xYourDeployedContractAddress"
abi = [...]  # Paste your compiled ABI JSON here
trust_contract = w3.eth.contract(address=contract_address, abi=abi)

# Submit trust status to Ethereum
alice_eth_address = "0x1234567890abcdef1234567890abcdef12345678"
tx_hash = trust_contract.functions.setTrustStatus(alice_eth_address, alice_trust_status).transact({'from': w3.eth.accounts[0]})
w3.eth.waitForTransactionReceipt(tx_hash)

# Verify trust status on-chain
is_trusted_on_chain = trust_contract.functions.isTrusted(alice_eth_address).call()
print(f"On-chain: Is Alice trusted? {is_trusted_on_chain}")
