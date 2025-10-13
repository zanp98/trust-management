#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Missing .env (run: make env)"; exit 1;
fi
source .env

if [ -z "${CONTRACT_ADDRESS:-}" ]; then
  echo "❌ CONTRACT_ADDRESS is not set in .env (run: make deploy)"; exit 1
fi

echo "🔎 Reading trust decision from chain (default evaluator → entity)…"
python3 src/read_trustgraph.py "$@"
