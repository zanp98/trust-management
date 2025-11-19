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

# terminal B – deploy and exercise the DON
make deploy      # deploy TrustGraph.sol & write address into .env
make don-up      # start aggregator + Pfizer/Moderna/DHL oracle nodes (Docker)
make request     # issue a trust-report request (default subject from .env or pass ARGS="http://example.org/...") 
# ...inspect docker logs / on-chain state...
make don-down    # stop the DON stack when finished
```

Key scripts live under `scripts/` and can be run directly. `scripts/request_report.sh` mirrors the pytest oracle-flow test: it hashes the subject, calls `requestTrustReport`, and polls `getTrustMetrics` until fulfilment (configurable via `.env`).

### Identity modes & DIDs

- `IDENTITY_MODE=URI` hashes namespace-based URIs such as `http://example.org/trust#Pfizer`.
- `IDENTITY_MODE=DID` canonicalises `did:ethr` identifiers (with optional `DID_ETHR_NETWORK`). Set `DID_ALLOW_NAMES_FALLBACK=true` while migrating legacy namespace labels; disable once every request uses a DID or raw Ethereum address.
- The DON request script reads `DON_SUBJECT` from `.env`; override per run via `make request ARGS="http://example.org/trust#DHL"`.

### Optional verifiable credentials

Provide or mint verifiable credentials (e.g., GDP compliance) for the relevant entities and point `VC_PATHS` at the bundle (comma-separated). Each oracle node:

1. Loads the descriptors via `identity_utils.gather_vc_facts` and injects the boolean fact (default `hasGDPVC`) into its evaluation logic.
2. Includes the credential hash + revocation flag inside every signed report.

The aggregator loads the same bundle, verifies that submitted hashes match a non-revoked VC, and only then records `OracleReportRecorded` on-chain. See `docs/vc_did_integration.md` for a deeper dive into the VC/DID flow.

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
- **Credential verification failures** – ensure `VC_PATHS` points to the credential bundle seen by both oracle nodes and the aggregator (comma-separated paths); restart services after updating the files.

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
3. **Oracle evaluation** – The dockerised Pfizer/Moderna/DHL nodes (see `docker-compose.yml`) run `oracle/node/oracle_node.py` with per-actor policy folders and `EVALUATION_MODE` (`hybrid`, `vc_only`, or `telemetry`). They watch `TrustOracleRequested`, refresh ontology + VC extras, execute their algorithm, and sign a canonical `OracleReport`.
4. **Publishing on-chain** – The aggregator service collects signed reports via `/reports`, immediately calls `recordOracleSubmission` (recording every `(actor → subject)` metric), and once quorum is met calls `fulfillTrustReport` to store the EMA consensus under `keccak256("MINI_DON_EVALUATOR")`.
5. **Requesting & monitoring** – Use `make request` (→ `scripts/request_report.sh`) to hash a subject, call `requestTrustReport`, and wait until `getTrustMetrics` reflects the fulfilment. Inspect `OracleReportRecorded` / `TrustOracleFulfilled` events or call the read-only getters to audit outcomes.
6. **Optional credentials** – When `VC_PATHS` points to a credential bundle, oracle nodes inject the boolean fact (e.g., `hasGDPVC`) and include the credential hash in every signed report. The aggregator cross-checks hashes/revocation state before recording submissions, guaranteeing the DON ignores expired or tampered VCs.
7. **Mini-DON stack** – `docs/oracle/README.md` documents the full flow plus additional settings (e.g., `NODE_EVALUATOR_MAP`, per-node policy directories, monitoring hooks) so you can plug in additional actors or replace the sample evaluation modes with bespoke codebases.

Together, these steps provide: (a) a shared ontology and policy store for trust criteria, (b) a repeatable evaluation workflow with explainable artefacts on disk, and (c) an immutable on-chain registry of the resulting trust decisions.
