#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "ERROR: Missing .env (run: make env)"; exit 1;
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

REQUIRED_VARS=("RPC_URL" "CONTRACT_ADDRESS")
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: Environment variable $var is required in .env"; exit 1;
  fi
done

SUBJECT_INPUT="${1:-${ORACLE_REPORT_SUBJECT:-${DON_SUBJECT:-}}}"
REQUEST_INPUT="${2:-${ORACLE_REPORT_REQUEST_ID:-}}"
FROM_BLOCK="${ORACLE_REPORT_FROM_BLOCK:-0}"
TO_BLOCK="${ORACLE_REPORT_TO_BLOCK:-latest}"

export RPC_URL
export CONTRACT_ADDRESS
export SUBJECT_INPUT
export REQUEST_INPUT
export FROM_BLOCK
export TO_BLOCK

python3 - <<'PY'
import json
import os
from typing import Optional
from web3 import Web3

rpc = os.environ["RPC_URL"]
contract_address = os.environ["CONTRACT_ADDRESS"]
subject_input = os.environ.get("SUBJECT_INPUT", "").strip()
request_input = os.environ.get("REQUEST_INPUT", "").strip()
from_block_raw = os.environ.get("FROM_BLOCK", "0")
to_block = os.environ.get("TO_BLOCK", "latest")

w3 = Web3(Web3.HTTPProvider(rpc))
with open("out/TrustGraph.sol/TrustGraph.json", encoding="utf-8") as fh:
    abi = json.load(fh)["abi"]
contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)


def normalize_hash(value: str, allow_text: bool) -> Optional[str]:
    if not value:
        return None
    if value.startswith("0x"):
        if len(value) != 66:
            raise SystemExit(f"Invalid hex length for {value}")
        return value.lower()
    if not allow_text:
        raise SystemExit(f"Expected hex string (0x...) but got {value}")
    return Web3.to_hex(Web3.keccak(text=value))


subject_hash = normalize_hash(subject_input, allow_text=True)
request_id = normalize_hash(request_input, allow_text=False)

try:
    from_block = int(from_block_raw)
except ValueError as exc:
    raise SystemExit(f"Invalid FROM_BLOCK {from_block_raw}") from exc

filters = {}
if request_id:
    filters["requestId"] = Web3.to_bytes(hexstr=request_id)
if subject_hash:
    filters["subject"] = Web3.to_bytes(hexstr=subject_hash)

kwargs = {"from_block": from_block, "to_block": to_block}
if filters:
    kwargs["argument_filters"] = filters

logs = contract.events.OracleReportRecorded().get_logs(**kwargs)

if not logs:
    print("WARN: No OracleReportRecorded events found for the given filters")
    raise SystemExit(0)

for ev in logs:
    args = ev["args"]
    print("request_id : 0x" + args["requestId"].hex())
    print("evaluator  : 0x" + args["evaluator"].hex())
    print("subject    : 0x" + args["subject"].hex())
    print("decision   :", bool(args["decision"]))
    print("score      :", int(args["score"]))
    print("flags      :", int(args["flags"]))
    print("as_of      :", int(args["asOf"]))
    print("policy     : 0x" + args["policyHash"].hex())
    print("credential : 0x" + args["credentialHash"].hex())
    print("node       :", args["node"])
    print("-")
PY
