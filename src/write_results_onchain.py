import json
import os
from pathlib import Path
from typing import Iterable, List
import pandas as pd
from dotenv import load_dotenv
from web3 import Web3
from web3.contract import Contract

TRUST_GRAPH_ABI = json.load(open("out/TrustGraph.sol/TrustGraph.json"))["abi"]



def _load_env() -> dict:
    load_dotenv()
    cfg = {
        "rpc_url": os.getenv("RPC_URL"),
        "contract_address": os.getenv("CONTRACT_ADDRESS"),
        "private_key": os.getenv("PRIVATE_KEY"),
        "namespace": os.getenv("NAMESPACE", "http://example.org/trust#"),
        "csv_path": os.getenv("TRUST_RESULTS_CSV", "results/trust_eval_hybrid_round1.csv"),
    }
    missing = [k for k, v in cfg.items() if v in (None, "") and k != "namespace"]
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    return cfg


def _normalise_namespace(namespace: str) -> str:
    namespace = namespace or ""
    if not namespace:
        return ""
    return namespace.rstrip("#/")


def _to_uri(label: str, namespace: str) -> str:
    if label.startswith("http://") or label.startswith("https://"):
        return label
    base = _normalise_namespace(namespace)
    if not base:
        return label
    return f"{base}#{label}"


def _hash_identifiers(values: Iterable[str], namespace: str) -> List[bytes]:
    w3 = Web3()
    hashed = []
    for val in values:
        uri = _to_uri(str(val), namespace)
        hashed.append(bytes(w3.keccak(text=uri)))
    return hashed


def _load_contract(w3: Web3, address: str) -> Contract:
    checksum = w3.to_checksum_address(address)
    return w3.eth.contract(address=checksum, abi=TRUST_GRAPH_ABI)


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


def main():
    cfg = _load_env()
    csv_path = Path(cfg["csv_path"])
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    df = pd.read_csv(csv_path)
    required_cols = {"Evaluator", "Entity", "CombinedDecision"}
    if not required_cols.issubset(df.columns):
        raise ValueError(f"CSV must contain columns: {sorted(required_cols)}")

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to RPC endpoint")

    account = w3.eth.account.from_key(cfg["private_key"])
    contract = _load_contract(w3, cfg["contract_address"])

    evaluators = _hash_identifiers(df["Evaluator"], cfg["namespace"])
    entities = _hash_identifiers(df["Entity"], cfg["namespace"])
    decisions = [_to_bool(val) for val in df["CombinedDecision"]]

    tx = contract.functions.batchSetTrustDecisions(
        evaluators,
        entities,
        decisions,
    ).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gasPrice": w3.eth.gas_price,
        }
    )

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print("Submitted trust results to blockchain")
    print(f"Tx hash: {receipt.transactionHash.hex()}")


if __name__ == "__main__":
    main()
