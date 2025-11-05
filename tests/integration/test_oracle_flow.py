import json
import os
import sys
import time
from pathlib import Path

import pytest
from dotenv import load_dotenv
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from identity_utils import IdentityHasher


load_dotenv()

if os.getenv("RUN_ORACLE_FLOW_TEST", "0") != "1":
    pytest.skip(
        "Set RUN_ORACLE_FLOW_TEST=1 to exercise the oracle + aggregator flow.",
        allow_module_level=True,
    )

if not Path("out/TrustGraph.sol/TrustGraph.json").exists():
    pytest.skip(
        "TrustGraph artifact missing (run `forge build` or `make deploy` first).",
        allow_module_level=True,
    )


ABI_PATH = Path("out/TrustGraph.sol/TrustGraph.json")
SUMMARY_TIMEOUT = float(os.getenv("ORACLE_FLOW_TIMEOUT", "60"))
POLL_INTERVAL = float(os.getenv("ORACLE_FLOW_POLL_INTERVAL", "2"))
DON_EVALUATOR_ID = Web3.keccak(text="MINI_DON_EVALUATOR")


def _load_contract(w3: Web3, address: str):
    artifact = json.loads(ABI_PATH.read_text(encoding="utf-8"))
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=artifact["abi"])


def _send_transaction(w3: Web3, account, tx_fn):
    tx = tx_fn.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 500_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"Transaction {tx_hash.hex()} failed with status {receipt.status}")
    return receipt


def test_oracle_flow_records_decision():
    required = ("RPC_URL", "CONTRACT_ADDRESS", "PRIVATE_KEY", "AGGREGATOR_PRIVATE_KEY")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        pytest.skip(f"Missing environment vars for oracle flow test: {', '.join(missing)}")

    w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
    if not w3.is_connected():
        pytest.skip("Unable to connect to RPC_URL")

    contract = _load_contract(w3, os.environ["CONTRACT_ADDRESS"])
    admin = w3.eth.account.from_key(os.environ["PRIVATE_KEY"])
    aggregator = w3.eth.account.from_key(os.environ["AGGREGATOR_PRIVATE_KEY"])

    current_agg = contract.functions.getAggregator().call()
    if current_agg.lower() != aggregator.address.lower():
        _send_transaction(w3, admin, contract.functions.setAggregator(aggregator.address))

    hasher = IdentityHasher(
        identity_mode=os.getenv("IDENTITY_MODE", "URI"),
        namespace=os.getenv("NAMESPACE", "http://example.org/trust#"),
        did_network=os.getenv("DID_ETHR_NETWORK", ""),
        allow_namespace_fallback=os.getenv("DID_ALLOW_NAMES_FALLBACK", "true").lower() != "false",
    )

    subject_label = os.getenv("ORACLE_TEST_SUBJECT", "http://example.org/trust#Pfizer")
    try:
        subject_hash = hasher.hash_single(subject_label)
    except Exception as err:
        pytest.skip(f"Unable to hash test subject {subject_label!r}: {err}")

    baseline = contract.functions.getTrustMetrics(subject_hash).call()
    baseline_as_of = baseline[3]

    _send_transaction(
        w3,
        admin,
        contract.functions.requestTrustReport(subject_hash, int(os.getenv("ORACLE_TEST_TTL", "900"))),
    )

    deadline = time.time() + SUMMARY_TIMEOUT
    metrics = baseline
    while time.time() < deadline:
        metrics = contract.functions.getTrustMetrics(subject_hash).call()
        if metrics[3] > baseline_as_of and metrics[4] != bytes(32):
            break
        time.sleep(POLL_INTERVAL)
    else:
        pytest.fail("Aggregator did not fulfil the trust report within timeout")

    assert metrics[0] in (True, False), "Decision must be boolean"
    don_decision = contract.functions.getTrustDecision(DON_EVALUATOR_ID, subject_hash).call()
    assert don_decision == metrics[0]
