# VC & DID Integration Overview

This document captures how verifiable credentials (VCs) and decentralised identifiers (DIDs) flow through the current trust-management prototype. Use it as the narrative backbone when writing about identity, provenance, and oracle validation in the thesis.

## 1. Artefact lifecycle

1. **Issuance**  
   - `src/issue_vc.py` (or an external issuer) creates JSON-LD credentials for actors such as transporters or distributors.  
   - Each VC links back to an ontology entity via `credentialSubject.id` (URI or DID).
   - Credentials are stored off-chain under `credentials/` (or any path referenced via `VC_PATHS`).  
   - Hashing: we canonicalise the payload (`json.dumps(..., sort_keys=True)`) and take Keccak-256. This hash is what ends up on-chain.

2. **Static evaluation (`make eval`)**  
   - `src/run_hybrid_eval.py --vc ...` loads credentials via `identity_utils.gather_vc_facts`.  
   - For every subject with a non-revoked VC, we inject the boolean fact `hasGDPVC = 1` into the evaluator (`TrustEvaluatorExt.set_extra_facts`).  
   - Policies (`policies/*.json`) now reference `hasGDPVC`: e.g. Pfizer only trusts distributors that present the credential.  
   - Output CSVs get extra columns: `VCPath`, `CredentialHash`, `VCRevoked`. These are reused later for on-chain publishing.

3. **On-chain publishing (`make publish`)**  
   - `src/write_results_onchain.py` inspects the CSV.  
     * If any row has a credential hash (either precomputed in `CredentialHash` or available via `VCPath`), it calls `batchSetTrustDecisionsWithCredentials`.  
     * Rows without credentials submit `0x00…00` as the hash; rows with credentials send the VC hash beside the decision.  
   - This keeps the contract lean: we only anchor hashes, not the full credential.

## 2. Oracle & aggregator workflow

Both services run inside Docker (see `docker-compose.yml`) and share VC settings via environment variables:

| Variable | Purpose |
|----------|---------|
| `VC_PATHS` | Comma-separated list of folders/files containing VC JSON/JSON-LD. Default: `credentials/issued`. |
| `VC_PROPERTY` | Ontology property set to `1.0` when a VC exists (defaults to `hasGDPVC`). |
| `IDENTITY_MODE` / `NAMESPACE` / `DID_*` | Ensure canonicalisation matches evaluation/publish scripts. |

### Oracle (`oracle/node/oracle_node.py`)

1. **Startup**: loads VC descriptors, computes hashes (`identity_utils.gather_vc_facts`), seals them into `_vc_metadata`, and sets `_vc_extras` so the evaluator sees `hasGDPVC = 1`.
2. **Before each request**: refreshes the ontology from Fuseki and re-applies `_vc_extras`.
3. **Evaluation**:  
   - Runs `TrustEvaluatorExt` (with VC extras) and isolates rows for the requested subject.  
   - Computes a per-subject `credential_hash`: the first matching VC hash (or zero if none).  
   - Builds `OracleReport` including that hash; if the VC is flagged as revoked, sets `FLAG_VC_REVOKED`.
4. **Signing**: the canonical JSON (now containing `credential_hash`) is signed with the node’s private key and sent to the aggregator.

### Aggregator (`oracle/aggregator/aggregator.py`)

1. **Startup**: loads the same VC descriptors, builds a lookup map `subject_hash → {hash_bytes, revoked}`.
2. **Receiving reports**: stores signed reports until quorum is met.  
3. **Aggregation**:  
   - Verifies all reports agree on subject, policy hash, and credential hash.  
   - Checks the aggregated hash against the local VC store; if mismatched or revoked, raises `CredentialValidationError`.  
   - If validation fails, it logs a warning and drops the request (no crash).  
4. **Fulfilment**: valid aggregates call `TrustGraph.fulfillTrustReport`, storing the credential hash under the special evaluator `keccak256("MINI_DON_EVALUATOR")`.

## 3. Smart contract touchpoints

`TrustGraph.sol` already supported credential hashes before the DON work:

- `setTrustDecisionWithCredential` and `batchSetTrustDecisionsWithCredentials` store the supplied `bytes32` hash alongside each evaluator/entity pair.
- `fulfillTrustReport` now accepts the credential hash inside `OracleReport`, so the DON writes both decision and provenance for the subject.
- Consumers read the hash via `getCredentialHash(evaluator, entity)` and reconcile it with the off-chain VC.

## 4. Data flow summary

```
Issuer --> VC JSONLD (credentials/...) --> evaluator --> CSV (CredentialHash column)
                                      \                              |
                                       \--> oracle/aggregator (VC_PATHS) --> report.credential_hash

CSV --> write_results_onchain.py --> TrustGraph.batchSetTrustDecisionsWithCredentials
DON reports --> aggregator --> TrustGraph.fulfillTrustReport
```

All components use the same `IdentityHasher` logic, so URIs and `did:ethr` values map deterministically to hashes. This avoids the classic “double hashing” pitfall when writing or reading contract state.

## 5. Testing / failure scenarios

- `tests/test_identity_utils.py` covers VC parsing, hashing, and `gather_vc_facts`.  
- `tests/integration/test_oracle_flow.py` exercises the full DON path when `RUN_ORACLE_FLOW_TEST=1`.  
- To simulate a revoked credential:
  1. Set `credentialStatus.revoked` to `true` in the VC JSON.
  2. Restart the stack (`docker compose up -d --build aggregator oracle_node`).
  3. Run the integration test; the aggregator logs a warning and skips fulfilment because the VC is revoked (`CredentialValidationError`).

## 6. Tidbits for the thesis

- **Why off-chain storage?** Reduces on-chain cost, keeps PII out of the contract, and aligns with VC best practices: chain stores hashes, not documents.
- **Deterministic canonicalisation** ensures the same hash regardless of field order—critical for cross-language verification.
- **Security hooks**: revoked credentials set a flag (`FLAG_VC_REVOKED`) and stop fulfilment; mismatched hashes are ignored, preventing a malicious report from sneaking in.
- **Extensibility**: `VC_PROPERTY` is pluggable—switch it to `hasGMPVC` or introduce multiple credentials by expanding `_extra_facts` and policy schema.

Refer back here when documenting identity provenance, oracle guarantees, or any compliance/privacy narrative in the thesis.
