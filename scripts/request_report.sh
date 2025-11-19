#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Missing .env (run: make env)"; exit 1;
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

REQUIRED_VARS=("RPC_URL" "CONTRACT_ADDRESS" "PRIVATE_KEY")
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "❌ Environment variable $var is required in .env"; exit 1;
  fi
done

if ! command -v cast >/dev/null 2>&1; then
  echo "❌ 'cast' CLI not found (install Foundry: https://book.getfoundry.sh/getting-started/installation)"; exit 1;
fi

SUBJECT_LABEL="${1:-${DON_SUBJECT:-http://example.org/trust#DHL}}"
TTL="${DON_TTL:-900}"
TIMEOUT="${DON_TIMEOUT:-180}"
POLL_INTERVAL="${DON_POLL_INTERVAL:-5}"

SUBJECT_HASH=$(cast keccak "$SUBJECT_LABEL")
export SUBJECT_HASH
export RPC_URL
export CONTRACT_ADDRESS
export DON_TIMEOUT="$TIMEOUT"
export DON_POLL_INTERVAL="$POLL_INTERVAL"

BASELINE_AS_OF=$(python3 - <<'PY'
import json
import os
from web3 import Web3

rpc = os.environ["RPC_URL"]
contract_address = os.environ["CONTRACT_ADDRESS"]
subject = os.environ["SUBJECT_HASH"]

w3 = Web3(Web3.HTTPProvider(rpc))
with open("out/TrustGraph.sol/TrustGraph.json", encoding="utf-8") as fh:
    abi = json.load(fh)["abi"]
contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
subject_bytes = bytes.fromhex(subject[2:] if subject.startswith("0x") else subject)
metrics = contract.functions.getTrustMetrics(subject_bytes).call()
print(metrics[3])
PY
)
export BASELINE_AS_OF

echo "ℹ️  Baseline as_of=$BASELINE_AS_OF for $SUBJECT_LABEL ($SUBJECT_HASH)"
echo "📝 Sending requestTrustReport ttl=$TTL ..."

cast send \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  "$CONTRACT_ADDRESS" \
  "requestTrustReport(bytes32,uint64)" \
  "$SUBJECT_HASH" \
  "$TTL"

echo "⏳ Waiting up to ${TIMEOUT}s for aggregator fulfilment ..."
python3 - <<'PY'
import json
import os
import time
from web3 import Web3

rpc = os.environ["RPC_URL"]
contract_address = os.environ["CONTRACT_ADDRESS"]
subject = os.environ["SUBJECT_HASH"]
baseline = int(os.environ["BASELINE_AS_OF"])
timeout = float(os.environ.get("DON_TIMEOUT", "180"))
poll = float(os.environ.get("DON_POLL_INTERVAL", "5"))

w3 = Web3(Web3.HTTPProvider(rpc))
with open("out/TrustGraph.sol/TrustGraph.json", encoding="utf-8") as fh:
    abi = json.load(fh)["abi"]
contract = w3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
subject_bytes = bytes.fromhex(subject[2:] if subject.startswith("0x") else subject)

deadline = time.time() + timeout
while time.time() < deadline:
    metrics = contract.functions.getTrustMetrics(subject_bytes).call()
    decision, score, flags, as_of, policy_hash = metrics
    if as_of > baseline and any(policy_hash):
        print("✅ Trust report fulfilled")
        print(f"    decision : {decision}")
        print(f"    score    : {score}")
        print(f"    flags    : {flags}")
        print(f"    as_of    : {as_of}")
        print(f"    policy   : 0x{policy_hash.hex()}")
        break
    time.sleep(poll)
else:
    raise SystemExit("❌ Timeout waiting for aggregator fulfilment")
PY
