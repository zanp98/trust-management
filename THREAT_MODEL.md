# THREAT_MODEL.md  
**Trust Management System — Hybrid Threat Model**

---

## 1. Overview

| Layer | Role | Main Technologies |
|-------|------|-------------------|
| **Blockchain** | Immutable storage and decision registry | Ethereum / TrustGraph.sol / Foundry |
| **Ontology & Knowledge Base (TrustKB)** | Semantic reasoning, entity modeling, policy inference | Apache Jena Fuseki, OWL 2, SPARQL |
| **Evaluator & Scripts** | Hybrid trust algorithm, identity hashing, VC issuance | Python 3.10 +, `src/` scripts, Makefile |
| **Connector & CLI** | Data exchange between layers | REST / SPARQL / Web3.py |
| **Users & Identities** | Evaluators, manufacturers, distributors, regulators | DIDs / URIs / Ethereum addresses |

---

## 2. Threat-Modeling Approach

- **Base frameworks:**  
  - STRIDE → security threats  
  - LINDDUN → privacy threats  
- **Extended dimension:** “Semantic & Economic Context” → ontology drift, reasoning abuse, incentive manipulation.  
- **Method:** per-component DFD + threat enumeration → likelihood/impact matrix → mitigations.

---

## 3. Threat Inventory by Component

### 3.1 Blockchain Layer

| Category | Threat | Description | Compatibility (STRIDE) | Mitigation |
|-----------|---------|-------------|-------------------------|-------------|
| **Spoofing** | Unauthorized contract call | Attacker writes decisions without evaluator key | ✅ | `onlyEvaluator` modifier + multi-sig |
| **Tampering** | Smart-contract state overwrite | Reentrancy / storage aliasing | ✅ | Checks-effects-interactions pattern |
| **Repudiation** | Evaluator denies publishing | ✅ | On-chain signature + VC link |
| **DoS** | Gas exhaustion via large batch | ✅ | Batch limit + split transactions |
| **Elevation of privilege** | Exploit proxy/admin role | ✅ | Role-based auth + OpenZeppelin AccessControl |
| **Economic attack** | Selfish publishing / collusion | ⚠️ (partially covered) | Require multi-party endorsement + stake penalties |

---

### 3.2 Ontology & Fuseki Layer

| Category | Threat | Description | Compatibility | Mitigation |
|-----------|---------|-------------|---------------|-------------|
| **Tampering** | Ontology modification | Unauthorized OWL update | ✅ | Hash ontology on each run + read-only dataset |
| **Information Disclosure** | SPARQL data leak | Sensitive triples exposed | ✅ | Auth & role-based queries + minimal export |
| **Data Poisoning** | Malicious triples alter reasoning | ⚠️ (new semantic threat) | Validate ontology consistency + reasoner check |
| **Inference Attack** | Combine public triples to re-ID entity | ✅ (LINDDUN Linkability) | Hash entity IRIs + limit cross-graph joins |
| **Non-compliance** | Personal data on immutable store | ✅ | Keep PII off-chain; only hashed references stored |

---

### 3.3 Evaluator & Scripts Layer

| Category | Threat | Description | Compatibility | Mitigation |
|-----------|---------|-------------|---------------|-------------|
| **Input Validation** | CSV/JSON injection | Malicious fields bypass rules | ✅ | Schema validation (JSONSchema, CSV sanity check) |
| **Replay Attack** | Re-publishing old evaluations | ✅ | Timestamp & run-manifest hash check |
| **Privilege Escalation** | Local script executes as admin | ✅ | Least-privilege execution; sudo ban |
| **Data Poisoning** | Biased input series (EWMA drift) | ⚠️ | Sliding-window & anomaly detector |
| **VC Forgery** | Invalid Ed25519 signatures | ✅ | DIDKit verify before publish |

---

### 3.4 Connector & Data Flows

| Flow | Threat | Description | Mitigation |
|------|---------|-------------|-------------|
| KB ↔ Evaluator | MITM intercept of SPARQL query | TLS + basic auth + query signature |
| Evaluator ↔ Blockchain | Wrong ID hash mapping | Canonical IdentityHasher + unit tests |
| Logs ↔ Storage | Leakage of entity names | Redact identifiers in logs |
| VC ↔ Publisher | Replay of old VC | Verify `exp` and nonce |

---

## 4. Privacy & LINDDUN Mapping

| LINDDUN Category | Example in System | Mitigation |
|-------------------|------------------|-------------|
| **Linkability** | Same entity hash across datasets | Salted hashes per dataset |
| **Identifiability** | VC subject correlates to real name | Use pseudonymous DIDs |
| **Non-repudiation** | Immutable logs leak behavior | Off-chain aggregates + VC revocation mechanism |
| **Detectability** | On-chain activity reveals role | Batch publishing / mixers |
| **Disclosure** | SPARQL dump reveals private metrics | Access control + aggregation |
| **Unawareness** | Participant not informed about data use | Consent logs / DPIA note |
| **Non-compliance** | GDPR rights vs. immutability | Off-chain personal data storage + deletion pointers |

---

## 5. Semantic & Economic Extensions

| Threat Type | Description | Impact Area | Countermeasure |
|--------------|-------------|-------------|----------------|
| **Ontology Poisoning** | Add false axioms to bias reasoner | Evaluation integrity | Ontology hash & consistency validation |
| **Semantic Drift** | Gradual policy change undermines rules | Trust policy consistency | Versioned policy hash + multi-sign approval |
| **Incentive Manipulation** | Evaluator collusion / self-promotion | Reputation layer | Stake slashing + cross-validation of scores |
| **Governance Capture** | One actor controls ontology & contract | Governance model | Multi-sig + rotating admin keys |
| **Sybil Injection** | Fake DIDs inflate trust | Identity system | DID verification + VC issuance policy |
| **Policy Bypass via Schema Drift** | CSV omits required column | Pipeline integrity | JSONSchema validation in CI |

---

## 6. Residual Risk Matrix

| Threat | Likelihood | Impact | Residual Risk Level | Notes |
|---------|-------------|--------|--------------------|-------|
| Ontology tamper | Low | High | Medium | Hash + read-only dataset sufficient |
| Identity collision | Low | High | Medium | Canonical Hasher verified |
| Replay CSV | Medium | Medium | Low | Manifest check in publisher |
| VC forgery | Low | High | Low | DIDKit signature verification |
| Incentive collusion | Medium | High | Medium | Mitigated by multi-evaluator approach |

---

## 7. Compliance & Governance Notes

- **GDPR alignment:** personal data kept off-chain; only hashes on-chain.  
- **eIDAS 2.0 / VCs:** follow W3C VC Data Model v2 and DID ethr method.  
- **Regulatory mapping:** supports EU Pharmaceutical Strategy and Falsified Medicines Directive via traceability and auditable logs.  
- **Security testing:** adversarial scripts for replay, Sybil, poisoning, DoS.  
- **Privacy impact:** DPIA appendix to this file covers linkability and retention.

---

## 8. References

- Van Landuyt et al., *On the Applicability of Security and Privacy Threat Modeling for Blockchain Applications*, SecPre 2019.  
- Kochovski et al., *Drug Traceability System Based on Semantic Blockchain and Reputation Method*, 2024.  
- Kayhan, *Ensuring Trust in Pharmaceutical Supply Chains by Data Protection-by-Design Approach to Blockchains*, 2022.  
- Shemov et al., *Blockchain Applied to the Construction Supply Chain — Threat Model*, 2020.  