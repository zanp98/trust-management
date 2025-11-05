import argparse
import json
import os
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
from web3 import Web3
from web3.contract import Contract

from identity_utils import (
    IdentityHasher,
    IdentityError,
    load_vc,
    credential_hash,
)

TRUST_GRAPH_ABI = json.load(open("out/TrustGraph.sol/TrustGraph.json"))["abi"]


def _load_env() -> dict:
    load_dotenv()
    cfg = {
        "rpc_url": os.getenv("RPC_URL"),
        "contract_address": os.getenv("CONTRACT_ADDRESS"),
        "private_key": os.getenv("PRIVATE_KEY"),
        "namespace": os.getenv("NAMESPACE", "http://example.org/trust#"),
        "identity_mode": os.getenv("IDENTITY_MODE", "URI"),
        "did_network": os.getenv("DID_ETHR_NETWORK", ""),
        "allow_did_fallback": os.getenv("DID_ALLOW_NAMES_FALLBACK", "true"),
        "csv_path": os.getenv("TRUST_RESULTS_CSV", "results/trust_eval_hybrid_round1.csv"),
    }
    missing = [
        key
        for key, value in cfg.items()
        if value in (None, "")
        and key
        not in {
            "namespace",
            "did_network",
            "allow_did_fallback",
        }
    ]
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    return cfg


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


def _parse_cli_args(argv=None):
    parser = argparse.ArgumentParser(description="Publish trust evaluation results on-chain.")
    parser.add_argument(
        "--csv",
        dest="csv_path",
        help="Override the CSV file path (defaults to TRUST_RESULTS_CSV from .env).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging for identity normalisation and transaction details.",
    )
    return parser.parse_args(argv)


def _hex_to_bytes32(value: str) -> bytes:
    data = value.strip()
    if not data:
        return bytes(32)
    if data.startswith(("0x", "0X")):
        data = data[2:]
    raw = bytes.fromhex(data)
    if len(raw) != 32:
        raise ValueError(f"Credential hash must be 32 bytes (got {len(raw)} bytes)")
    return raw


def _extract_credential_hashes(df: pd.DataFrame) -> tuple[bool, list[bytes]]:
    use_credentials = False
    hashes: list[bytes] = []
    vc_cache: dict[str, bytes] = {}
    for _, row in df.iterrows():
        hash_hex = ""
        if "CredentialHash" in df.columns:
            value = row["CredentialHash"]
            if isinstance(value, str):
                hash_hex = value.strip()
            elif pd.notna(value):
                hash_hex = str(value).strip()
        if not hash_hex and "VCPath" in df.columns:
            raw_path = row["VCPath"]
            if isinstance(raw_path, str) and raw_path.strip():
                canon_path = raw_path.strip()
                if canon_path not in vc_cache:
                    descriptor = load_vc(canon_path)
                    vc_cache[canon_path] = credential_hash(descriptor)
                hash_hex = "0x" + vc_cache[canon_path].hex()
        if hash_hex:
            use_credentials = True
            hashes.append(_hex_to_bytes32(hash_hex))
        else:
            hashes.append(bytes(32))
    return use_credentials, hashes


def main(argv=None):
    args = _parse_cli_args(argv)
    cfg = _load_env()
    if args.csv_path:
        cfg["csv_path"] = args.csv_path

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

    allow_fallback = _to_bool(cfg["allow_did_fallback"])
    hasher = IdentityHasher(
        identity_mode=cfg["identity_mode"],
        namespace=cfg["namespace"],
        did_network=cfg["did_network"],
        allow_namespace_fallback=allow_fallback,
        debug=args.debug,
    )

    try:
        evaluators = hasher.hash_many(df["Evaluator"])
        entities = hasher.hash_many(df["Entity"])
    except IdentityError as err:
        raise ValueError(f"Failed to normalise identifiers: {err}") from err

    decisions = [_to_bool(val) for val in df["CombinedDecision"]]

    if args.debug:
        print("[publish] Prepared payload size:", len(decisions))

    use_credentials, credential_hashes = _extract_credential_hashes(df)

    if use_credentials:
        fn = contract.functions.batchSetTrustDecisionsWithCredentials(
            evaluators,
            entities,
            decisions,
            credential_hashes,
        )
    else:
        fn = contract.functions.batchSetTrustDecisions(
            evaluators,
            entities,
            decisions,
        )

    tx = fn.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gasPrice": w3.eth.gas_price,
        }
    )

    if args.debug:
        print("[publish] Transaction preview:", tx)

    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    if args.debug:
        print(f"[publish] Submitted tx hash: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print("Submitted trust results to blockchain")
    print(f"Tx hash: {receipt.transactionHash.hex()}")


if __name__ == "__main__":
    main()
