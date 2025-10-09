from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("RPC_URL")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ABI_PATH = "out/TrustGraph.sol/TrustGraph.json"

w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "Napaka pri povezavi z node"

# Naloži ABI
import json
abi = json.load(open(ABI_PATH))["abi"]

contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)

# --- Primer: preveri ali Pfizer zaupa DHL ---
namespace = os.getenv("NAMESPACE", "http://example.org/trust#")
pfizer = Web3.keccak(text=f"{namespace}Pfizer")
dhl = Web3.keccak(text=f"{namespace}DHL")

is_trusted = contract.functions.getTrustDecision(pfizer, dhl).call()
print(f"Pfizer → DHL trusted? {is_trusted}")

# --- Opcijsko: preberi vse dogodke ---
events = contract.events.TrustResultRecorded.create_filter(from_block=0).get_all_entries()
for e in events:
    print(e["args"])
