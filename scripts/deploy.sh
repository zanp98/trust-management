#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Manjka .env (pognaj: make env)"; exit 1;
fi
source .env

if ! command -v forge >/dev/null 2>&1; then
  echo "❌ Manjka 'forge' (Foundry). Namesti: curl -L https://foundry.paradigm.xyz | bash && foundryup"; exit 1;
fi

CONTRACT_PATH="chain/contracts/TrustGraph.sol:TrustGraph"

echo "🧱 Deployam TrustGraph na $RPC_URL …"
OUT_JSON=$(forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast \
  --json \
  "$CONTRACT_PATH")

ADDR=$(echo "$OUT_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("deployedTo",""))')

if [ -z "$ADDR" ]; then
  echo "❌ Ne najdem naslova pogodbe v izpisu. Output:"
  echo "$OUT_JSON"
  exit 1
fi

# zapiši v .env (če ključa še ni ali ga zamenjaj)
if grep -q "^CONTRACT_ADDRESS=" .env; then
  sed -i.bak "s|^CONTRACT_ADDRESS=.*|CONTRACT_ADDRESS=$ADDR|g" .env && rm -f .env.bak
else
  echo "CONTRACT_ADDRESS=$ADDR" >> .env
fi

echo "✅ TrustGraph deployed: $ADDR"
