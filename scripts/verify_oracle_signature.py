#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from eth_account.messages import encode_defunct
from web3 import Web3

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional helper for local runs
    load_dotenv = None

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for path in (ROOT, SRC_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from identity_utils import IdentityHasher  # noqa: E402
from oracle.common.report import OracleReport, SignedOracleReport  # noqa: E402


def _parse_bool(raw: str) -> bool:
    value = str(raw or "").strip().lower()
    if value in ("1", "true", "yes", "y"):
        return True
    if value in ("0", "false", "no", "n"):
        return False
    raise ValueError(f"Invalid boolean value: {raw!r}")


def _parse_hex_bytes(raw: str, size: int) -> bytes:
    value = str(raw or "").strip()
    if value.startswith(("0x", "0X")):
        value = value[2:]
    data = bytes.fromhex(value) if value else b""
    if len(data) != size:
        raise ValueError(f"Expected {size} bytes, received {len(data)}")
    return data


def _compute_policy_hash(policy_dir: Path) -> bytes:
    if not policy_dir.exists():
        return bytes(32)
    policies = []
    for path in sorted(policy_dir.glob("*.json")):
        policies.append(json.loads(path.read_text(encoding="utf-8")))
    if not policies:
        return bytes(32)
    serialised = [json.dumps(policy, sort_keys=True) for policy in policies]
    joined = "|".join(sorted(serialised))
    return bytes(Web3.keccak(text=joined))


def _report_url(endpoint: str) -> str:
    base = endpoint.rstrip("/")
    if base.endswith("/reports"):
        return base
    return f"{base}/reports"


def _post_report(url: str, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            print(f"aggregator_response: {resp.status} {data}")
    except urllib.error.HTTPError as err:
        data = err.read().decode("utf-8") if err.fp else ""
        raise SystemExit(f"Aggregator rejected report ({err.code}): {data}") from err


def main() -> int:
    if load_dotenv:
        load_dotenv()

    parser = argparse.ArgumentParser(
        description="Sign an OracleReport, recover the signer, and optionally submit it to the aggregator.",
    )
    parser.add_argument("--subject", default=os.getenv("ORACLE_TEST_SUBJECT") or os.getenv("DON_SUBJECT") or "http://example.org/trust#Pfizer")
    parser.add_argument("--decision", default=os.getenv("ORACLE_TEST_DECISION", "true"))
    parser.add_argument("--score", type=int, default=int(os.getenv("ORACLE_TEST_SCORE", "9000")))
    parser.add_argument("--flags", type=int, default=int(os.getenv("ORACLE_TEST_FLAGS", "0")))
    parser.add_argument("--as-of", dest="as_of", type=int, default=int(os.getenv("ORACLE_TEST_AS_OF", "0")))
    parser.add_argument("--policy-hash", default=os.getenv("ORACLE_TEST_POLICY_HASH", "auto"))
    parser.add_argument("--credential-hash", default=os.getenv("ORACLE_TEST_CREDENTIAL_HASH", "0x" + "00" * 32))
    parser.add_argument("--private-key", default=os.getenv("ORACLE_PRIVATE_KEY") or os.getenv("PRIVATE_KEY"))
    parser.add_argument("--request-id", default=os.getenv("ORACLE_REQUEST_ID", ""))
    parser.add_argument("--aggregator-endpoint", default=os.getenv("AGGREGATOR_ENDPOINT", ""))
    parser.add_argument("--post", action="store_true", help="POST the signed report to the aggregator endpoint.")
    args = parser.parse_args()

    if not args.private_key:
        raise SystemExit("Missing private key (set ORACLE_PRIVATE_KEY or pass --private-key)")

    hasher = IdentityHasher(
        identity_mode=os.getenv("IDENTITY_MODE", "URI"),
        namespace=os.getenv("NAMESPACE", "http://example.org/trust#"),
        did_network=os.getenv("DID_ETHR_NETWORK", ""),
        allow_namespace_fallback=os.getenv("DID_ALLOW_NAMES_FALLBACK", "true").lower() != "false",
    )

    subject_hash = hasher.hash_single(args.subject)
    decision = _parse_bool(args.decision)
    as_of = args.as_of or int(time.time())
    if args.policy_hash == "auto":
        policy_hash = _compute_policy_hash(ROOT / "policies")
    else:
        policy_hash = _parse_hex_bytes(args.policy_hash, 32)
    credential_hash = _parse_hex_bytes(args.credential_hash, 32)

    report = OracleReport(
        subject=subject_hash,
        decision=decision,
        score=args.score,
        flags=args.flags,
        as_of=as_of,
        policy_hash=policy_hash,
        credential_hash=credential_hash,
    )

    w3 = Web3()
    signable = encode_defunct(text=report.to_canonical_json())
    signature = w3.eth.account.sign_message(signable, private_key=args.private_key).signature
    node_id = w3.eth.account.from_key(args.private_key).address.lower()
    signed_report = SignedOracleReport(report=report, node_id=node_id, signature=signature)

    recovered = w3.eth.account.recover_message(signable, signature=signature).lower()
    print("subject_hash:", Web3.to_hex(subject_hash))
    print("report_json :", report.to_canonical_json())
    print("signature   :", Web3.to_hex(signature))
    print("node_id     :", node_id)
    print("recovered   :", recovered)
    print("match       :", recovered == node_id)

    if recovered != node_id:
        return 2

    if args.post or args.aggregator_endpoint:
        if not args.aggregator_endpoint:
            raise SystemExit("Missing aggregator endpoint (set AGGREGATOR_ENDPOINT or pass --aggregator-endpoint)")
        if not args.request_id:
            raise SystemExit("Missing request id (set ORACLE_REQUEST_ID or pass --request-id)")
        request_id = args.request_id
        if not request_id.startswith("0x"):
            request_id = f"0x{request_id}"
        payload = {"request_id": request_id, "report": signed_report.to_serialisable()}
        _post_report(_report_url(args.aggregator_endpoint), payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
