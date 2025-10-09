#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  echo "❌ Manjka .env (pognaj: make env)"; exit 1;
fi
source .env

mkdir -p results logs

# Če uporabljaš svoj obstoječi eval skript, ga kliči tukaj.
# Primer: obstoječ skript iz tvojega posta že generira CSV v results/.
# Če imaš 'src/run_hybrid_eval.py', ga kliči; sicer uporabi tvoj glavni eval skript.

if [ -f "src/run_hybrid_eval.py" ]; then
  echo "🧠 Hibridna evalvacija (src/run_hybrid_eval.py)…"
  python src/run_hybrid_eval.py
else
  echo "🧠 Evalvacija (obstoječi skript)…"
  python src/main.py 2>/dev/null || true
  # ↑ zamenjaj 'src/main.py' z dejanskim fajlom, ki generira results/trust_evaluation_results.csv
fi

# Preprost log metapodatkov (ontologija/politike hash itd.), če želiš:
TS=$(date +"%Y%m%d-%H%M%S")
python - <<'PY'
import hashlib, json, os, glob, time
from pathlib import Path

env = {k:v for k,v in os.environ.items() if k in ("OWL_PATH","POLICIES_DIR","NAMESPACE")}
def keccak_file(path):
    try:
        import sha3  # pip install pysha3 (opcijsko), sicer fallback na sha256
    except Exception:
        sha = hashlib.sha256()
    else:
        sha = hashlib.sha3_256()
    with open(path,'rb') as f:
        sha.update(f.read())
    return "0x"+sha.hexdigest()

owl = os.getenv("OWL_PATH","ontologies/pharma-trust.owl")
ont_hash = keccak_file(owl) if os.path.exists(owl) else None

pol_dir = os.getenv("POLICIES_DIR","policies")
pol_hashes = {}
if os.path.isdir(pol_dir):
    for p in sorted(glob.glob(os.path.join(pol_dir,"*.json"))):
        pol_hashes[os.path.basename(p)] = keccak_file(p)

log = {
  "timestamp": int(time.time()),
  "ontologyHash": ont_hash,
  "policyHashes": pol_hashes,
  "env": env
}
Path("logs").mkdir(exist_ok=True)
with open(f"logs/run-{int(time.time())}.json","w") as f:
    json.dump(log, f, indent=2)
print("📝 Zapisal logs/run-*.json")
PY
