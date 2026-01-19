# Workflows

Two perspectives drive the trust-management system today:

1. **EMA / authority** – requests a fresh trust decision from the decentralized oracle network (DON) before approving a shipment or certifying a partner.
2. **Actor-level due diligence** – e.g., Pfizer wants to review its own policy verdict (Pfizer → DHL) before deciding whether to collaborate with DHL.

Both rely on the same primitives (TrustGraph.sol, oracle nodes, aggregator) but the entry points differ. The sections below capture each workflow step-by-step.

---

## 1. EMA requests a DON evaluation

**Purpose:** obtain the latest consensus decision for a subject (e.g., DHL) by asking every oracle node to re-evaluate and record results on-chain.

| Step | Actor | Action |
|------|-------|--------|
| 1 | EMA operator | Run `make request ARGS="http://example.org/trust#DHL"` (wrapper around `scripts/request_report.sh`). The script hashes the subject, logs the current `getTrustMetrics` baseline, and sends `requestTrustReport(subjectHash, ttl)` using the EMA private key from `.env`. |
| 2 | TrustGraph | Emits `TrustOracleRequested(requestId, subject, deadline)` and stores the pending request. |
| 3 | Oracle nodes (Pfizer hybrid, Moderna VC-only, DHL telemetry by default) | Detect the event, refresh ontology + VC extras, run their configured algorithm (`EVALUATION_MODE`), sign `OracleReport`, and POST to `aggregator:8080/reports`. |
| 4 | Aggregator | Verifies signatures, calls `recordOracleSubmission(requestId, evaluatorHash, report, credentialHash, nodeAddress)` for each payload (so `(Pfizer → DHL)`, `(Moderna → DHL)`, etc. are written on-chain immediately), waits for quorum, aggregates the boolean/score/flags, then calls `fulfillTrustReport`. |
| 5 | TrustGraph | Updates `subjectMetrics[subject]`, emits `TrustOracleFulfilled`, and the EMA script stops polling once it sees the `as_of` timestamp advance. The script prints the final decision/score/flags/policy hash. |
| 6 | Post-check | Optional `cast call` summaries: <br> `getTrustMetrics(subject)` for the consensus, and <br> `oracleSubmissions(evaluatorHash, subject)` to inspect each actor’s raw report (hash evaluator IDs via `cast keccak "http://example.org/trust#Pfizer"`). |

**When to run:** every time EMA wants the DON’s real-time answer. This entirely replaces the legacy “generate CSV → publish” pipeline; a single `make request` triggers the full loop and logs both individual submissions and the aggregated view on-chain.

---

## 2. Pfizer evaluates whether to trust a partner

**Purpose:** Pfizer (or any actor with a node) checks its own stance toward another entity—either by inspecting the latest recorded submission or by triggering the DON/request themselves for updated data.

### Option A – Read the latest Pfizer → DHL verdict

Once the aggregator has written `OracleReportRecorded`, Pfizer (or a tooling dashboard) can gather the most recent numbers without re-running the DON:

1. Compute evaluator hash: `PFIZER_HASH=$(cast keccak "http://example.org/trust#Pfizer")`.  
2. Subject hash (e.g., DHL): `SUBJECT_HASH=$(cast keccak "http://example.org/trust#DHL")`.  
3. Query the stored metrics:  
   ```bash
   cast call \
     --rpc-url $RPC_URL \
     $CONTRACT_ADDRESS \
     "oracleSubmissions(bytes32,bytes32)((bool,uint256,uint256,uint64,bytes32,bytes32,address,bytes32))" \
     $PFIZER_HASH \
     $SUBJECT_HASH
   ```
4. The tuple reveals Pfizer’s decision (`bool`), score (basis points), flags bitfield, timestamp, policy hash, credential hash, node address, and the originating `requestId`.

This is Pfizer’s current opinion, signed off and anchored on-chain. If Moderna wants to inspect its own view, swap the evaluator hash.

### Option B – Trigger a re-evaluation themselves

Pfizer can also request a re-check (just like EMA) if it wants fresh telemetry:

1. Call `requestTrustReport(subjectHash, ttl)` with Pfizer’s admin key (or run `make request` with a subject they care about).  
2. Their node recomputes the decision and posts a new report; the aggregator records it and optionally aggregates the full DON result if quorum is met.
3. They read back the latest `oracleSubmissions(PfizerHash, subjectHash)` to confirm the updated data.

**Use cases:** onboarding a new logistics partner, verifying that a manufacturer still meets Pfizer’s policy, or auditing past decisions via immutable event logs (`OracleReportRecorded`).

---

## Notes

- **Evaluator mappings** come from `NODE_EVALUATOR_MAP` (e.g., `0x7099… = http://example.org/trust#Pfizer`). Ensure every oracle node’s Ethereum address is listed there so the aggregator can attribute submissions correctly.
- **VC hashes / revocation** are enforced off-chain and on-chain: the nodes embed the credential hash in their signed report; the aggregator cross-checks it against the local VC store before calling `recordOracleSubmission`.
- **Policy divergence** is intentional: Pfizer/Moderna/DHL may run different code or weighting; the aggregator simply records whatever each actor states. Only the final EMA consensus (from `fulfillTrustReport`) collapses them into a single decision. If you want unanimity instead of majority, adjust the aggregator’s aggregation logic or quorum.
