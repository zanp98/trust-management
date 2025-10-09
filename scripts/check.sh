#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Manjka .env (pognaj: make env)"; exit 1;
fi
source .env

if [ -z "${CONTRACT_ADDRESS:-}" ]; then
  echo "❌ CONTRACT_ADDRESS ni nastavljen v .env (pognaj: make deploy)"; exit 1
fi

echo "🔎 Primer branja iz verige (Pfizer → DHL)…"
python3 src/read_trustgraph.py
