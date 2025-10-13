#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Missing .env (run: make env)"; exit 1;
fi
source .env

mkdir -p results logs

# If you rely on a custom evaluation script, call it here instead.
# By default we expect src/run_hybrid_eval.py to produce CSV files under results/.

if [ -f "src/run_hybrid_eval.py" ]; then
  echo "🧠 Hybrid evaluation (src/run_hybrid_eval.py)…"
  python3 src/run_hybrid_eval.py "$@"
else
  echo "🧠 Evaluation (custom script fallback)…"
  python3 src/main.py "$@" 2>/dev/null || true
  # ↑ replace 'src/main.py' with your actual script that generates results/trust_evaluation_results.csv
fi

# Lightweight metadata log (ontology/policy hashes)
TS=$(date +"%Y%m%d-%H%M%S")
python3 - <<'PY'
import glob
import hashlib
import json
import os
import time
from pathlib import Path

env = {k: v for k, v in os.environ.items() if k in ("OWL_PATH", "POLICIES_DIR", "NAMESPACE")}


def keccak_file(path):
    try:
        import sha3  # optional: pip install pysha3, otherwise fall back to sha256
    except Exception:
        sha = hashlib.sha256()
    else:
        sha = hashlib.sha3_256()
    with open(path, "rb") as fh:
        sha.update(fh.read())
    return "0x" + sha.hexdigest()


owl = os.getenv("OWL_PATH", "ontologies/pharma-trust.owl")
ont_hash = keccak_file(owl) if os.path.exists(owl) else None

pol_dir = os.getenv("POLICIES_DIR", "policies")
pol_hashes = {}
if os.path.isdir(pol_dir):
    for path in sorted(glob.glob(os.path.join(pol_dir, "*.json"))):
        pol_hashes[os.path.basename(path)] = keccak_file(path)

log = {
    "timestamp": int(time.time()),
    "ontologyHash": ont_hash,
    "policyHashes": pol_hashes,
    "env": env,
}
Path("logs").mkdir(exist_ok=True)
with open(f"logs/run-{int(time.time())}.json", "w") as fh:
    json.dump(log, fh, indent=2)
print("📝 Wrote logs/run-*.json")
PY
