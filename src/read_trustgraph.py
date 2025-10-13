import argparse
import json
import os

from dotenv import load_dotenv
from web3 import Web3

from identity_utils import IdentityHasher, IdentityError


def _load_env():
    load_dotenv()
    cfg = {
        "rpc_url": os.getenv("RPC_URL"),
        "contract_address": os.getenv("CONTRACT_ADDRESS"),
        "namespace": os.getenv("NAMESPACE", "http://example.org/trust#"),
        "identity_mode": os.getenv("IDENTITY_MODE", "URI"),
        "did_network": os.getenv("DID_ETHR_NETWORK", ""),
        "allow_did_fallback": os.getenv("DID_ALLOW_NAMES_FALLBACK", "true"),
        "demo_evaluator": os.getenv("DEMO_EVALUATOR", "Pfizer"),
        "demo_entity": os.getenv("DEMO_ENTITY", "DHL"),
        "abi_path": os.getenv("TRUST_GRAPH_ABI", "out/TrustGraph.sol/TrustGraph.json"),
    }
    missing = [key for key in ("rpc_url", "contract_address") if not cfg[key]]
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    return cfg


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


def _load_contract(w3: Web3, address: str, abi_path: str):
    with open(abi_path) as fh:
        abi = json.load(fh)["abi"]
    return w3.eth.contract(address=w3.to_checksum_address(address), abi=abi)


def main():
    cfg = _load_env()

    parser = argparse.ArgumentParser(description="Query TrustGraph for a single trust decision.")
    parser.add_argument("--evaluator", default=cfg["demo_evaluator"], help="Evaluator DID/URI")
    parser.add_argument("--entity", default=cfg["demo_entity"], help="Entity DID/URI")
    parser.add_argument(
        "--skip-events",
        action="store_true",
        help="Skip printing TrustResultRecorded events",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging when normalising identities.",
    )
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        raise ConnectionError("Failed to connect to the RPC endpoint")

    contract = _load_contract(w3, cfg["contract_address"], cfg["abi_path"])
    allow_fallback = _to_bool(cfg["allow_did_fallback"])
    hasher = IdentityHasher(
        identity_mode=cfg["identity_mode"],
        namespace=cfg["namespace"],
        did_network=cfg["did_network"],
        allow_namespace_fallback=allow_fallback,
        debug=args.debug,
    )

    try:
        evaluator_hash = hasher.hash_single(args.evaluator)
        entity_hash = hasher.hash_single(args.entity)
    except IdentityError as err:
        raise ValueError(f"Unable to compute trust lookup identifiers: {err}") from err

    if args.debug:
        print(f"[check] Evaluator hash: 0x{evaluator_hash.hex()}")
        print(f"[check] Entity hash: 0x{entity_hash.hex()}")

    decision = contract.functions.getTrustDecision(evaluator_hash, entity_hash).call()
    print(
        f"{hasher.canonical(args.evaluator)} → {hasher.canonical(args.entity)} trusted? {bool(decision)}"
    )

    if not args.skip_events:
        events = contract.events.TrustResultRecorded.create_filter(from_block=0).get_all_entries()
        for event in events:
            print(event["args"])


if __name__ == "__main__":
    main()
