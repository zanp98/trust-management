#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Missing .env (run: make env)"; exit 1;
fi
source .env

if ! command -v forge >/dev/null 2>&1; then
  echo "❌ Missing 'forge' (Foundry). Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"; exit 1;
fi

CONTRACT_PATH="chain/contracts/TrustGraph.sol:TrustGraph"

echo "🧱 Deploying TrustGraph to $RPC_URL …"
OUT_JSON=$(forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast \
  --json \
  "$CONTRACT_PATH")

ADDR=$(echo "$OUT_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("deployedTo",""))')

if [ -z "$ADDR" ]; then
  echo "❌ Unable to read contract address from forge output:"
  echo "$OUT_JSON"
  exit 1
fi

# Update CONTRACT_ADDRESS in .env (create or replace)
if grep -q "^CONTRACT_ADDRESS=" .env; then
  sed -i.bak "s|^CONTRACT_ADDRESS=.*|CONTRACT_ADDRESS=$ADDR|g" .env && rm -f .env.bak
else
  echo "CONTRACT_ADDRESS=$ADDR" >> .env
fi

echo "✅ TrustGraph deployed: $ADDR"
