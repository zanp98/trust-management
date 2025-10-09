#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Manjka .env (pognaj: make env)"; exit 1;
fi
source .env

if [ -z "${CONTRACT_ADDRESS:-}" ]; then
  echo "❌ CONTRACT_ADDRESS ni nastavljen v .env (pognaj: make deploy)"; exit 1
fi

echo "🧾 Zapisujem rezultate na verigo @ $CONTRACT_ADDRESS …"
python3 src/write_results_onchain.py
echo "✅ Publish končan"
