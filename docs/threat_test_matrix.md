# Threat-to-Test Matrix

This matrix maps each mitigation from `THREAT_MODEL.md` to at least one concrete validation activity. Populate the **Owner** and **Status** columns as work progresses, and link to the exact test artifact once it exists (unit test, integration scenario, monitoring rule, etc.).

| Layer / Flow | Threat | Mitigation (per `THREAT_MODEL.md`) | Planned Test Coverage | Artifact / Link | Status | Owner |
|--------------|--------|------------------------------------|-----------------------|-----------------|--------|-------|
| Blockchain (TrustGraph.sol) | Unauthorized contract call | `onlyEvaluator` modifier + multi-sig (Table 3.1) | Foundry unit tests that simulate non-evaluator callers and multisig requirements | `tests/foundry/AccessControl.t.sol` | Automated | TBD |
| Blockchain (TrustGraph.sol) | Smart-contract state overwrite | Checks-effects-interactions pattern | Foundry reentrancy tests + invariant fuzzing for storage integrity | `tests/foundry/Reentrancy.t.sol` | Automated | TBD |
| Blockchain (TrustGraph.sol) | Evaluator denies publishing | On-chain signature + VC link | Foundry test asserting publisher address and credential hash are recorded on-chain | `tests/foundry/PublishWithCredential.t.sol` | Automated | TBD |
| Blockchain (TrustGraph.sol) | Gas exhaustion via large batch | Batch limit + split transactions | Gas regression test ensuring batch limit enforces revert thresholds | `tests/foundry/BatchLimit.t.sol` | Automated | TBD |
| Blockchain (TrustGraph.sol) | Proxy/admin role abuse | Role-based auth via OpenZeppelin AccessControl | Unit tests for role assignment, revocation, and privileged function protection | `tests/foundry/AccessControl.t.sol` | Automated | TBD |
| Blockchain (TrustGraph.sol) | Economic collusion | Multi-party endorsement + stake penalties | Simulation script checking endorsement majority and penalty triggers | `tests/simulations/economic_collusion.py` | Automated | TBD |
| Ontology & Fuseki | Ontology tampering | Hash ontology each run + read-only dataset | CI job verifying ontology checksum and dataset permissions | `scripts/checks/verify_ontology_hash.py` (existing/new) | Planned | TBD |
| Ontology & Fuseki | SPARQL data leak | Auth + role-based queries, minimal export | Functional tests hitting Fuseki endpoints with unauthorized roles | `tests/integration/fuseki_access_test.py` (new) | Planned | TBD |
| Ontology & Fuseki | Data poisoning | Validate ontology consistency + reasoner check | Reasoner regression test injecting malicious triples and ensuring detection | `tests/ontology/poisoning_regression.py` (new) | Planned | TBD |
| Ontology & Fuseki | Inference attack | Hash entity IRIs + limit cross-graph joins | Privacy test confirming salted hashes and blocked cross-graph joins | `tests/privacy/hash_salt_test.py` (new) | Planned | TBD |
| Ontology & Fuseki | Non-compliance (PII) | Keep PII off-chain; hashed references only | Data pipeline check ensuring no raw PII leaves preprocessing | `tests/pipeline/pii_guard_test.py` (new) | Planned | TBD |
| Evaluator & Scripts | CSV/JSON injection | Schema validation (JSONSchema, CSV checks) | Pytest suite validating schema rejection of malformed inputs | `tests/validator/test_schema_guard.py` (new) | Planned | TBD |
| Evaluator & Scripts | Replay attack | Timestamp & run-manifest hash check | Integration test re-submitting past manifest to confirm rejection | `tests/integration/replay_guard_test.py` (new) | Planned | TBD |
| Evaluator & Scripts | Privilege escalation | Least privilege execution | CI lint ensuring scripts lack sudo usage + runtime check for permission escalation | `tests/security/least_privilege_test.py` (new) | Planned | TBD |
| Evaluator & Scripts | Data poisoning (drift) | Sliding-window & anomaly detector | Statistical test suite validating drift detector on synthetic biased data | `tests/anomaly/detector_regression.py` (new) | Planned | TBD |
| Evaluator & Scripts | VC forgery | EBSI verify before publish | Unit tests covering VC verification/hashing helpers and EBSI client behaviour | `tests/test_vc_utils.py`, `tests/test_ebsi_client.py` | Automated | TBD |
| Connectors & Flows | MITM on SPARQL | TLS + basic auth + query signature | Integration test with TLS off / invalid signature to ensure rejection | `tests/integration/connector_tls_test.py` (new) | Planned | TBD |
| Connectors & Flows | Wrong ID hash mapping | Canonical IdentityHasher + unit tests | Unit tests comparing expected identity hashes for known fixtures | `tests/unit/test_identity_hasher.py` (existing/new) | Planned | TBD |
| Connectors & Flows | Log leakage | Redact identifiers in logs | Log parsing test verifying redaction regex on sample outputs | `tests/unit/test_log_redaction.py` (new) | Planned | TBD |
| Connectors & Flows | VC replay | Verify `exp` and nonce | Integration test replaying stale VC to ensure rejection | `tests/integration/vc_replay_test.py` (new) | Planned | TBD |
| Privacy (LINDDUN) | Linkability | Salted hashes per dataset | Regression test ensuring salt rotation per dataset config | `tests/privacy/salted_hash_rotation_test.py` (new) | Planned | TBD |
| Privacy (LINDDUN) | Identifiability | Pseudonymous DIDs | Compliance test making sure generated DIDs lack direct PII | `tests/privacy/did_pseudonymity_test.py` (new) | Planned | TBD |
| Privacy (LINDDUN) | Detectability | Batch publishing / mixers | Simulation measuring on-chain timing correlation before/after batching | `tests/simulations/detectability_analysis.py` (new) | Planned | TBD |
| Privacy (LINDDUN) | Disclosure | Access control + aggregation | Access-control regression to ensure aggregates only | `tests/privacy/aggregation_guard_test.py` (new) | Planned | TBD |
| Semantic & Economic | Ontology poisoning | Hash & consistency validation | Duplicate of ontology tampering tests; ensure reasoner catches injected axioms | See `tests/ontology/poisoning_regression.py` | Planned | TBD |
| Semantic & Economic | Semantic drift | Versioned policy hash + multi-sign approval | Monitoring test verifying hash bump & multi-signature review on policy update | `tests/monitoring/policy_drift_monitor.py` (new) | Planned | TBD |
| Semantic & Economic | Incentive manipulation | Stake slashing + cross-validation | Simulation of colluding evaluators verifying stake penalties enactment | `tests/simulations/incentive_collusion.py` (new) | Planned | TBD |
| Semantic & Economic | Governance capture | Multi-sig + rotating admin keys | Unit test ensuring rotation schedule and multi-sig enforcement | `tests/foundry/GovernanceAccess.t.sol` (new) | Planned | TBD |
| Semantic & Economic | Sybil injection | DID verification + VC issuance policy | Integration test generating fake DIDs to ensure issuance policy rejects | `tests/integration/sybil_guard_test.py` (new) | Planned | TBD |
| Semantic & Economic | Policy bypass via schema drift | JSONSchema validation in CI | CI test ensuring schema changes fail without review | `tests/validator/test_schema_drift_guard.py` (new) | Planned | TBD |
| Oracle Node → Aggregator | Node spoofing / signature replay | Aggregator signature recovery + whitelist | AIOHTTP client test POSTing tampered payload to `/reports`, expecting 400 | `tests/integration/test_aggregator_guards.py::test_aggregator_signature_guard_rejects_tampered_payload` | Automated | TBD |
| Oracle Node → Aggregator | VC tampering / revoked credential | Aggregator cross-checks VC hash & revocation flag | Unit test invoking `aggregate_reports` with revoked credential metadata expecting `CredentialValidationError` | `tests/integration/test_aggregator_guards.py::test_aggregate_reports_rejects_revoked_vc` | Automated | TBD |
| Ontology & Fuseki | Ontology tampering | Hash ontology each run + read-only dataset | Unit test verifying `keccak_file` changes when ontology content is modified | `tests/ontology/test_ontology_hash_guard.py::test_keccak_file_detects_modification` | Automated | TBD |
| Ontology & Fuseki | Policy drift / tampering | Policy hash recorded with keccak | Unit test ensuring policy hash changes on mutation and is order invariant | `tests/ontology/test_policy_hash_guard.py` | Automated | TBD |

> **Usage Tips**
> - Update **Status** with values like `Planned`, `In Progress`, `Automated`, or `Monitored`.
> - When a test exists, replace `Artifact / Link` with the real path (or dashboard URL if external).
> - Add new rows for emergent threats; this document should evolve alongside `THREAT_MODEL.md`.
