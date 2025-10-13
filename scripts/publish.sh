#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Missing .env (run: make env)"; exit 1;
fi
source .env

if [ -z "${CONTRACT_ADDRESS:-}" ]; then
  echo "❌ CONTRACT_ADDRESS is not set in .env (run: make deploy)"; exit 1
fi

echo "🧾 Publishing evaluation results on-chain @ $CONTRACT_ADDRESS …"
python3 src/write_results_onchain.py "$@"
echo "✅ Publish finished"
