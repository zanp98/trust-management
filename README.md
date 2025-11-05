# Trust Management Toolkit

This repository brings together three pieces that support a pharma-oriented trust‑management demo:

1. **Blockchain workflow** – Make targets and scripts that deploy the `TrustGraph.sol` contract, evaluate trust policies, publish results on-chain, and query decisions.
2. **Identity handling** – Python helpers that normalise namespace URIs vs. `did:ethr` identifiers before writing/reading from the contract.
3. **TrustKB (Fuseki)** – A lightweight SPARQL client/CLI for maintaining the pharmaceutical ontology (`pharma-trust.owl`) inside an Apache Jena Fuseki dataset.

The sections below walk through setup for each component.

---

## Prerequisites

| Purpose | Requirement |
| --- | --- |
| Core tooling | Python 3.10+, `pip`, GNU Make |
| Smart contracts | Foundry (`anvil`, `forge`) |
| Optional DID tooling | DIDKit (if you issue/verify credentials) |
| Ontology triple store | Apache Jena Fuseki running at `http://localhost:3030` with dataset `trustkb` (Docker recipe provided) |

Install Python dependencies after cloning:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

---

## Environment configuration

Copy `.env.example` to `.env` and adjust values as needed:

```bash
cp .env.example .env
```

- **Fuseki** – set `FUSEKI_BASE_URL`, `FUSEKI_DATASET`, `FUSEKI_USER`, `FUSEKI_PASS`.
- **Ontology namespace** – `PHARM_NS` defaults to `http://www.semanticweb.org/zanp/ontologies/2024/10/trust-management-system#`.
- **Blockchain** – configure `RPC_URL`, `PRIVATE_KEY`, `CONTRACT_ADDRESS` (auto-populated after `make deploy`), plus trust-eval paths, identity mode, and optional VC flags.

---

## Blockchain workflow

Most day-to-day tasks are wrapped in the Makefile.

```bash
# initialise .env if it does not exist
make env

# terminal A – start local chain
make chain

# terminal B – step through the pipeline
make deploy      # deploy TrustGraph.sol & write address into .env
make eval        # run hybrid evaluation, emit CSV + logs (see scripts/eval.sh)
make publish     # hash identifiers and push results on-chain
make check       # read a sample trust decision (defaults to DEMO_EVALUATOR/ENTITY)

# or run the whole flow (deploy → eval → publish → check)
make demo
```

Key scripts live under `scripts/` and can be run directly; they honour `--debug` (forwarded from Make via `ARGS="--debug"`).

### Identity modes & DIDs

- `IDENTITY_MODE=URI` (default) hashes namespace-based URIs such as `http://example.org/trust#Pfizer`.
- `IDENTITY_MODE=DID` canonicalises `did:ethr` identifiers (with optional `DID_ETHR_NETWORK`). Set `DID_ALLOW_NAMES_FALLBACK=true` while migrating legacy namespace labels; disable once every CSV row uses a DID or raw Ethereum address.
- Demo lookups use `DEMO_EVALUATOR`/`DEMO_ENTITY`. Override via CLI, e.g. `scripts/check.sh --evaluator did:ethr:... --entity did:ethr:...`.

### Optional verifiable credentials

Credential support remains available but is disabled by default (`VC_ENABLED=false`). To require signed trust evaluations:

1. Provide or mint verifiable credentials (e.g., GDP compliance) for the relevant entities.
2. Run the evaluator with `src/run_hybrid_eval.py --vc credentials/*.jsonld` (or repeated `--vc path` flags).  
   This injects the boolean feature `hasGDPVC` (configurable via `--vc-property`) during rule evaluation and records both `VCPath` and `CredentialHash` columns in the output CSV.
3. `src/write_results_onchain.py` inspects those columns automatically: if any credential hash is present it switches to `batchSetTrustDecisionsWithCredentials`, forwarding zero hashes for rows without VCs.
4. The oracle + aggregator load the same VC bundle by reading `VC_PATHS` (comma-separated paths, default `credentials/issued`). The oracle sets `hasGDPVC` when a valid, non-revoked credential exists; the aggregator cross-checks submitted credential hashes against the local store before fulfilling.
5. (Optional) Set `VC_REQUIRED=true` so `make publish` or downstream scripts refuse to send rows missing credentials.

→ Detailed diagram of the VC/DID flow lives in `docs/vc_did_integration.md`.

---

## TrustKB (Fuseki integration)

### Start Fuseki locally

The bundled Compose file launches a Fuseki instance configured for the `trustkb` dataset:

```bash
docker compose up -d
```

Upload `pharma-trust.owl` via the Fuseki UI (`http://localhost:3030`) → dataset `trustkb` → Upload.

### CLI usage

All commands run inside the virtualenv (or prefix with `python -m venv .venv && …`):

```bash
# show help
python -m src.trustkb.cli --help

# list ontology classes
python -m src.trustkb.cli classes

# list registered manufacturers
python -m src.trustkb.cli list-manufacturers

# insert a manufacturer with optional trust score
python -m src.trustkb.cli add-manufacturer Pfizer --score 0.95

# link a trusted partner edge
python -m src.trustkb.cli trust Pfizer McKesson

# remove all triples for pharm:Pfizer
python -m src.trustkb.cli rm Pfizer

# hash the default graph (for anchoring on-chain)
python -m src.trustkb.cli graph-hash
```

To export the ontology/graph back to OWL/RDF:

```bash
curl -u "$FUSEKI_USER:$FUSEKI_PASS" \
  -H "Accept: application/rdf+xml" \
  "$FUSEKI_BASE_URL/$FUSEKI_DATASET/data" > pharma-trust-export.owl
```

or reuse `export_default_graph` from `src/trustkb/hashing.py` in a small Python script.

---

## Tests

```bash
. .venv/bin/activate
pytest -q
```

The smoke test hits the Fuseki `SELECT` endpoint; ensure the dataset is running (or skip/adjust in CI).

---

## Troubleshooting

- **Anvil/Fuseki not running** – `make chain` or `docker compose up -d` must be active before deploying/publishing.
- **Missing environment values** – scripts fail fast when required `.env` keys are absent; rerun `make env` and fill in secrets.
- **SPARQL auth errors** – confirm `FUSEKI_USER/FUSEKI_PASS` match your Fuseki admin credentials.
- **Identity errors** – when `IDENTITY_MODE=DID`, CSV values must be valid `did:ethr` identifiers or Ethereum addresses (with fallback enabled only during transition).
- **Credential verification failures** – ensure `VC_ENABLED` matches your dataset’s state, or set `VC_REQUIRED=false` while backfilling VCs.

---

## File map (high level)

- `Makefile` – automation for blockchain + TrustKB helpers (`install`, `run`, `add-mf`, `link`, `rm`, `hash`, `test`).
- `scripts/` – shell wrappers used by Make targets.
- `src/trustkb/` – Fuseki client, SPARQL templates, CLI, and hashing utilities.
- `src/read_trustgraph.py` / `src/write_results_onchain.py` – on-chain read/write paths with identity handling.
- `tests/test_trustkb.py` – Fuseki smoke test.

Feel free to adapt the CLI into APIs or additional automation as your workflow evolves.

---

## System overview

1. **Data sources** – The pharmaceutical knowledge base lives in Fuseki (`trustkb` dataset) and is seeded from `ontologies/pharma-trust.owl`. The CLI under `src/trustkb/` adds or amends triples that describe manufacturers, logistics partners, and quality metrics.
2. **Policies** – Trust requirements are maintained as JSON files in `policies/`. Each policy defines the evaluator, the actor types it vets, and property thresholds/weights used by the hybrid algorithm.
3. **Hybrid evaluation** – `make eval` (→ `scripts/eval.sh`) calls `src/run_hybrid_eval.py`, which loads the ontology plus every policy. The extended evaluator (`src/trust_evaluator_ext.py`) combines deterministic rule checking with a probabilistic Beta-EWMA model backed by `state/trust_stats.json`. It writes one or more CSVs under `results/` and records the ontology/policy hashes in `logs/run-*.json`.
4. **Publishing on-chain** – After deployment (`make deploy` → `scripts/deploy.sh`), `make publish` feeds the latest CSV to `src/write_results_onchain.py`. Identifiers are canonicalised and keccak-hashed via `IdentityHasher` (`src/identity_utils.py`). When `VC_ENABLED=true` the script also resolves, verifies, and hashes each credential via EBSI before calling `batchSetTrustDecisionsWithCredentials`; otherwise it falls back to `batchSetTrustDecisions`.
5. **Querying & monitoring** – `make check` (→ `scripts/check.sh`) uses `src/read_trustgraph.py` to normalise identities in the same way and query the contract. Contract state holds the authoritative decision bits, while the CSVs/logs on disk remain the auditable trail.
6. **Optional credentials** – When `VC_ENABLED=true`, issue verifiable credentials with `python -m src.issue_vc …` before publishing; `make publish` verifies them (via DIDKit/EBSI, depending on your configuration) before uploading results. Disable via `.env` while backfilling legacy data.
7. **Mini-DON prototype** – `docs/oracle/README.md` outlines how to turn the evaluator into a decentralised oracle network. `TrustGraph.sol` already exposes request/fulfil flows, and scaffolding for nodes/aggregator lives under `oracle/`.

Together, these steps provide: (a) a shared ontology and policy store for trust criteria, (b) a repeatable evaluation workflow with explainable artefacts on disk, and (c) an immutable on-chain registry of the resulting trust decisions.
