# Mini-DON Architecture (Oracle Prototype)

This directory sketches the moving parts required to turn the existing trust evaluator into a small decentralised oracle network.

## Components

| Layer | Path | Responsibility |
|-------|------|----------------|
| `chain/contracts/TrustGraph.sol` | Updated contract exposing `requestTrustReport` / `fulfillTrustReport`, storing aggregated metrics, and emitting events for oracle coordination. |
| `oracle/node/oracle_node.py` | Long-lived service that listens for on-chain requests, runs the Python trust evaluator, verifies credentials (EBSI), signs the result, and pushes it to the aggregator. |
| `oracle/aggregator/aggregator.py` | Collects signed reports from multiple nodes, enforces quorum, aggregates the score/flags, and submits a single transaction to `TrustGraph.sol`. |
| `oracle/common/report.py` | Shared dataclasses and canonical JSON helpers mirroring the on-chain `OracleReport` struct to keep signatures deterministic. |

## Flow

1. Admin (or another contract) calls `requestTrustReport(subject, ttl)` on `TrustGraph.sol`.
2. Each node receives the corresponding `TrustOracleRequested` event, executes the evaluation pipeline, and submits a signed report to the aggregator.
3. As each report arrives, the aggregator calls `recordOracleSubmission` so the raw `(evaluator → subject)` metrics and credential hash are persisted on-chain (`OracleReportRecorded`).
4. Once `>= quorum` reports are available, the aggregator aggregates them (median score, majority flags) and calls `fulfillTrustReport`.
5. The contract records the consensus decision under the special evaluator ID `keccak256("MINI_DON_EVALUATOR")`, stores metrics, emits `TrustOracleFulfilled`, and clears the pending request.

## Next Steps

The current code is scaffold-only. To turn it into a working DON:

1. **Oracle node** – the implementation now refreshes the ontology from Fuseki, enriches it with VC-derived facts (`hasGDPVC` by default), and includes the credential hash + revocation flag inside each signed report. Point it at your credential bundle via `VC_PATHS`.
2. **Aggregator** – the HTTP service (`POST /reports`) checks signatures, enforces quorum, validates VC hashes against the same bundle, and rejects revoked/mismatched credentials before calling `fulfillTrustReport`. Configure `VC_PATHS`, `ALLOWED_NODE_ADDRESSES`, `NODE_EVALUATOR_MAP`, and `AGGREGATOR_PRIVATE_KEY` before starting it. `NODE_EVALUATOR_MAP` is a comma-separated list of `0xNodeAddress=http://example.org/trust#Evaluator` pairs so every submission is attributed on-chain.
3. **Security** – pin policy/ontology versions via `policy_hash`, manage node keys (e.g., DID or Ethereum accounts), and protect the aggregator endpoint (mTLS, DID auth).
4. **Operations** – add monitoring, persistence (tracking last processed block), and Docker/compose definitions for local testing.

For an end-to-end narrative (VC issuance → evaluator → publisher → DON), see `docs/vc_did_integration.md`.

### Evaluation strategies

Oracle nodes can run different algorithms while still emitting the shared `OracleReport` struct. Set `EVALUATION_MODE` when starting a node:

| Mode | Description |
|------|-------------|
| `hybrid` (default) | Runs the full ontology + probabilistic pipeline (`TrustEvaluatorExt`). |
| `vc_only` | Approves a subject only if a non-revoked VC exists for it (pure credential gate). |
| `telemetry` | Uses lightweight telemetry metrics (from `TELEMETRY_PATH`, default `state/telemetry_metrics.json`) to derive a score/decision. |

Mix and match modes per actor: e.g., Pfizer can run `hybrid`, Moderna can run `vc_only`, and DHL can operate in `telemetry` mode focusing on IoT data.

## Containerised local stack

Running `docker compose up` at the repository root will start the following services:

| Service | Description |
|---------|-------------|
| `anvil` | Local Ethereum testnet (Foundry). |
| `fuseki` | Apache Jena Fuseki with the `trustkb` dataset. |
| `aggregator` | Python HTTP service exposing `/reports`, recording each submission, and relaying the aggregated result on-chain. |
| `oracle_node` | Pfizer node (hybrid mode) using the first Anvil account. |
| `oracle_moderna` | Moderna node (VC-only mode) using a second Anvil account. |
| `oracle_dhl` | DHL node (telemetry mode) demonstrating IoT-driven heuristics. |

```bash
docker compose up --build
```

Environment variables (with sensible defaults for local testing) can be overridden, e.g.:

```bash
CONTRACT_ADDRESS=0x... \
AGGREGATOR_PRIVATE_KEY=0x... \
ALLOWED_NODE_ADDRESSES=0xf39f...,0x7099... \
docker compose up
```

Replace the placeholder `CONTRACT_ADDRESS` once you deploy `TrustGraph.sol` inside the Anvil container. The sample private keys correspond to the default Anvil test accounts.

After the services are up you can trigger a request from another terminal using Foundry:

```bash
cast send \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  $CONTRACT_ADDRESS \
  "requestTrustReport(bytes32,uint64)" \
  $(cast keccak "http://example.org/trust#Pfizer") \
  3600
```

You should then see the oracle node log a new request, forward a signed report to the aggregator, and the aggregator submit `fulfillTrustReport` back to Anvil once quorum is met.

## End-to-end smoke test

1. **Start Anvil in Docker**
   ```bash
   cd docker
   docker compose -f docker-compose.don.yml up -d anvil
   ```

2. **Deploy `TrustGraph.sol` from your host**
   ```bash
   DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
   CONTRACT_ADDRESS=$(forge create \
     --rpc-url http://localhost:8545 \
     --private-key $DEPLOYER_PK \
     chain/contracts/TrustGraph.sol:TrustGraph | jq -r '.deployedTo')
   export CONTRACT_ADDRESS
   echo "Deployed TrustGraph at $CONTRACT_ADDRESS"
   ```

3. **Start aggregator + oracle node** (they will read `CONTRACT_ADDRESS`)
   ```bash
   export AGGREGATOR_PRIVATE_KEY=0x59c6995e998f97a5a0044966f094538c38e2f95b36f3c7a1972c569b9f298561
   export ORACLE_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
   export ALLOWED_NODE_ADDRESSES=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
   docker compose -f docker-compose.don.yml up --build aggregator oracle_node
   ```
   (Leave this terminal streaming logs; the aggregator exposes `POST /reports` on port 8080 and the node polls every 5 seconds.)

4. **Authorise the aggregator on-chain** (must be done before fulfilling)
   ```bash
   AGGREGATOR_ADDR=0x6B1dE84A57361CECfF64E21A14a2F95cd03472E9
   cast send \
     --rpc-url http://localhost:8545 \
     --private-key $DEPLOYER_PK \
     $CONTRACT_ADDRESS \
     "setAggregator(address)" \
     $AGGREGATOR_ADDR
   ```

5. **Request a trust report for Pfizer (hashed DID/URI)**
   ```bash
   SUBJECT_HASH=$(cast keccak "http://example.org/trust#Pfizer")
   cast send \
     --rpc-url http://localhost:8545 \
     --private-key $DEPLOYER_PK \
     $CONTRACT_ADDRESS \
     "requestTrustReport(bytes32,uint64)" \
     $SUBJECT_HASH \
     3600
   ```

6. **Observe the flow**
   - Oracle node should log the incoming request, run the evaluator, and POST a signed report.
   - Aggregator should log receipt, reach quorum (default 1), and submit `fulfillTrustReport`.
   - Anvil will show the transaction; the aggregator logs the tx hash.

7. **Verify results on-chain**
   ```bash
   cast call \
     --rpc-url http://localhost:8545 \
     $CONTRACT_ADDRESS \
     "getTrustMetrics(bytes32)(bool,uint256,uint256,uint64,bytes32)" \
     $SUBJECT_HASH
   ```
   You should see the boolean decision, score (basis points), flags bitfield, timestamp, and policy hash recorded.

8. **Clean up**
   ```bash
   docker compose down
   ```

This smoke test confirms that the evaluator logic, signing workflow, and on-chain fulfilment all work together using the containerised stack.

Use this scaffold to incrementally build the mini-DON while keeping the current evaluator scripts operational for backfill and regression testing.
