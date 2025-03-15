from rdflib import Graph, Namespace
from web3 import Web3

g = Graph()
g.parse("ontologies/trust.owl", format="application/rdf+xml")

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

# Example entity (Replace with dynamic input)
alice_uri = "http://example.org/trust#Alice"

# Run trust reasoner
alice_trust_status = is_trusted(alice_uri)
print(f"🟢 Trust Reasoning Result: Is Alice trusted? {alice_trust_status}")

# Step 2: Connect to Ethereum Blockchain (Anvil Testnet)
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

# Load Smart Contract
contract_address = "0x8464135c8F25Da09e49BC8782676a84730C318bC"  # Replace with actual contract address
abi = [
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": True,
				"internalType": "address",
				"name": "entity",
				"type": "address"
			},
			{
				"indexed": False,
				"internalType": "bool",
				"name": "isTrusted",
				"type": "bool"
			}
		],
		"name": "TrustUpdated",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "entity",
				"type": "address"
			}
		],
		"name": "isTrusted",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "entity",
				"type": "address"
			},
			{
				"internalType": "bool",
				"name": "isTrusted",
				"type": "bool"
			}
		],
		"name": "setTrustStatus",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "trustedEntities",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]

trust_contract = w3.eth.contract(address=contract_address, abi=abi)

# Use an unlocked account (From Anvil)
account = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Step 3: Send Trust Status to Smart Contract
alice_eth_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # Replace with correct Ethereum address
tx_hash = trust_contract.functions.setTrustStatus(alice_eth_address, alice_trust_status).transact({'from': account})
w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"✅ Trust status updated on-chain for Alice: {alice_trust_status}")

# Step 4: Retrieve Trust Status from Smart Contract
is_trusted_on_chain = trust_contract.functions.isTrusted(alice_eth_address).call()
print(f"🟢 On-chain Trust Check: Is Alice trusted? {is_trusted_on_chain}")
