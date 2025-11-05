# SPDX-License-Identifier: MIT
"""
Oracle node skeleton.

This service is responsible for:
  * watching `TrustOracleRequested` events emitted by `TrustGraph.sol`
  * fetching and verifying off-chain data (Fuseki, telemetry, DID/VC proofs)
  * running the trust evaluator for the requested subject
  * signing the resulting `OracleReport` and forwarding it to the aggregator

The implementation below is intentionally skeletal – it shows the plumbing,
leaving business logic hooks (`evaluate_subject`) for future work.
"""

from __future__ import annotations

import asyncio
import logging
import os
import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.contract import Contract

from oracle.common.report import OracleReport, SignedOracleReport
from identity_utils import IdentityHasher, gather_vc_facts
from trust_evaluator_ext import TrustEvaluatorExt

FLAG_NO_DATA = 1 << 0
FLAG_LOW_SCORE = 1 << 1
FLAG_DISAGREEMENT = 1 << 2
FLAG_VC_REVOKED = 1 << 3

LOG = logging.getLogger("oracle.node")

if os.getenv("ORACLE_DEBUGPY_PORT"):
    import debugpy

    host = os.getenv("ORACLE_DEBUGPY_HOST", "0.0.0.0")
    port = int(os.getenv("ORACLE_DEBUGPY_PORT", "5678"))
    LOG.info("debugpy listening on %s:%s; waiting for client...", host, port)
    debugpy.listen((host, port))
    debugpy.wait_for_client()


@dataclass
class NodeConfig:
    rpc_url: str
    contract_address: str
    private_key: str
    aggregator_endpoint: str
    ontology_path: str
    policies_dir: str
    stats_path: str
    identity_mode: str
    namespace: str
    did_network: str
    allow_namespace_fallback: bool = True
    poll_interval: float = 5.0
    fuseki_base_url: str = ""
    fuseki_dataset: str = "trustkb"
    fuseki_user: str = ""
    fuseki_pass: str = ""
    fuseki_accept: str = "text/turtle"
    fuseki_format: str = "turtle"
    vc_paths: List[str] = field(default_factory=list)
    vc_property: str = "hasGDPVC"


class OracleNode:
    def __init__(self, config: NodeConfig):
        self._config = config
        self._w3 = Web3(Web3.HTTPProvider(config.rpc_url))
        if not self._w3.is_connected():
            raise RuntimeError(f"Unable to connect to RPC at {config.rpc_url}")
        with open("out/TrustGraph.sol/TrustGraph.json", "r", encoding="utf-8") as fh:
            artifact = json.load(fh)
        self._contract: Contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(config.contract_address),
            abi=artifact["abi"],
        )
        self._account = self._w3.eth.account.from_key(config.private_key)
        self._last_block = self._w3.eth.block_number
        self._session: Optional[aiohttp.ClientSession] = None

        self._policies = self._load_policies(config.policies_dir)
        self._policy_hash = self._compute_policy_hash(self._policies)
        self._identity_hasher = IdentityHasher(
            identity_mode=config.identity_mode,
            namespace=config.namespace,
            did_network=config.did_network,
            allow_namespace_fallback=config.allow_namespace_fallback,
        )
        self._evaluator = TrustEvaluatorExt(
            owl_path=config.ontology_path,
            stats_path=config.stats_path,
        )
        self._vc_property = config.vc_property
        self._vc_extras, self._vc_metadata = gather_vc_facts(config.vc_paths, self._identity_hasher, self._vc_property)
        self._evaluator.set_extra_facts(self._vc_extras)
        if self._vc_metadata:
            LOG.info("loaded %d verifiable credential(s) for enrichment", len(self._vc_metadata))
        self._fuseki_base_url = config.fuseki_base_url.rstrip("/")
        self._fuseki_dataset = config.fuseki_dataset.strip("/")
        self._fuseki_user = config.fuseki_user
        self._fuseki_pass = config.fuseki_pass
        self._fuseki_accept = config.fuseki_accept
        self._fuseki_format = config.fuseki_format

    async def run(self) -> None:
        """Main event loop."""

        LOG.info("oracle node started; watching for TrustOracleRequested events")
        async with aiohttp.ClientSession() as session:
            self._session = session
            await self._refresh_ontology()
            while True:
                try:
                    await self._process_requests()
                except Exception as exc:  # pylint: disable=broad-except
                    LOG.exception("error while processing requests: %s", exc)
                await asyncio.sleep(self._config.poll_interval)

    async def _process_requests(self) -> None:
        current_block = self._w3.eth.block_number
        if current_block <= self._last_block:
            return
        logs = self._contract.events.TrustOracleRequested().get_logs(
            from_block=self._last_block + 1,
            to_block=current_block,
        )
        self._last_block = current_block
        for event in logs:
            await self._refresh_ontology()
            request_id = event["args"]["requestId"]
            subject = event["args"]["subject"]
            LOG.info("processing oracle request %s for subject %s", request_id.hex(), subject.hex())
            report = await self.evaluate_subject(subject)
            if report is None:
                LOG.warning("no report produced for %s; skipping", subject.hex())
                continue
            signed = self.sign_report(report)
            await self.submit_to_aggregator(request_id, signed)

    async def evaluate_subject(self, subject: bytes) -> Optional[OracleReport]:
        df = await asyncio.to_thread(self._run_full_evaluation)
        if df.empty:
            return None

        matching = self._rows_for_subject(df, subject)
        if not matching:
            LOG.warning("no evaluation rows found for subject %s", subject.hex())
            return None

        decisions = [bool(row["CombinedDecision"]) for row in matching]
        prob_scores = [float(row["ProbScore"]) for row in matching]

        decision = sum(decisions) * 2 >= len(decisions)
        score_basis_points = int(round(statistics.mean(prob_scores) * 10000))

        flags = 0
        if not matching:
            flags |= FLAG_NO_DATA
        if any(dec != decisions[0] for dec in decisions):
            flags |= FLAG_DISAGREEMENT
        if score_basis_points < 7000:
            flags |= FLAG_LOW_SCORE

        credential_hash, vc_revoked = self._credential_hash_for_rows(matching)
        if vc_revoked:
            flags |= FLAG_VC_REVOKED

        report = OracleReport(
            subject=subject,
            decision=decision,
            score=score_basis_points,
            flags=flags,
            as_of=int(time.time()),
            policy_hash=self._policy_hash,
            credential_hash=credential_hash,
        )
        LOG.info(
            "evaluated subject %s: decision=%s score=%s flags=0x%x", subject.hex(), decision, score_basis_points, flags
        )
        return report

    def sign_report(self, report: OracleReport) -> SignedOracleReport:
        message = report.to_canonical_json() #.encode("utf-8")
        # digest = Web3.keccak(message)
        signable = encode_defunct(text=message)
        signature = self._w3.eth.account.sign_message(signable, private_key=self._config.private_key).signature
        node_id = self._account.address
        return SignedOracleReport(report=report, node_id=node_id, signature=signature)

    async def submit_to_aggregator(self, request_id: bytes, signed_report: SignedOracleReport) -> None:
        """
        Send the signed report to the off-chain aggregator.
        In practice this would be an authenticated HTTP POST or gRPC call.
        """
        if self._session is None:
            raise RuntimeError("HTTP session not initialised")
        payload = {
            "request_id": Web3.to_hex(request_id),
            "report": signed_report.to_serialisable(),
        }
        url = f"{self._config.aggregator_endpoint.rstrip('/')}/reports"
        async with self._session.post(url, json=payload, timeout=10) as resp:
            if resp.status != 200:
                text = await resp.text()
                LOG.error("aggregator rejected report (%s): %s", resp.status, text)
            else:
                LOG.info("submitted report for %s to aggregator", request_id.hex())

    def _run_full_evaluation(self):
        temp_csv = Path("/tmp/oracle_eval.csv")
        df = self._evaluator.run_full_evaluation(self._policies, export_csv=str(temp_csv))
        if temp_csv.exists():
            temp_csv.unlink(missing_ok=True)
        return df

    def _rows_for_subject(self, df, subject: bytes) -> List[dict]:
        matching: List[dict] = []
        for row in df.to_dict(orient="records"):
            canonical_entity = self._identity_hasher.canonical(row["Entity"])
            hashed = Web3.keccak(text=canonical_entity)
            if hashed == subject:
                matching.append(row)
        return matching

    @staticmethod
    def _load_policies(folder: str):
        policies = []
        for policy_path in Path(folder).glob("*.json"):
            policies.append(json.loads(policy_path.read_text(encoding="utf-8")))
        return policies

    @staticmethod
    def _compute_policy_hash(policies) -> bytes:
        serialised = [json.dumps(policy, sort_keys=True) for policy in policies]
        joined = "|".join(sorted(serialised))
        return Web3.keccak(text=joined)

    async def _refresh_ontology(self) -> None:
        if self._session is None:
            raise RuntimeError("HTTP session not initialised")
        if self._fuseki_base_url:
            data_url = f"{self._fuseki_base_url}/{self._fuseki_dataset}/data"
            auth = None
            if self._fuseki_user:
                auth = aiohttp.BasicAuth(self._fuseki_user, self._fuseki_pass)
            try:
                async with self._session.get(
                    data_url,
                    headers={"Accept": self._fuseki_accept},
                    auth=auth,
                    timeout=10,
                ) as resp:
                    resp.raise_for_status()
                    payload = await resp.read()
                await asyncio.to_thread(self._evaluator.reload_from_bytes, payload, self._fuseki_format)
                self._evaluator.set_extra_facts(self._vc_extras)
                LOG.debug("ontology refreshed from Fuseki %s", data_url)
                return
            except Exception as exc:  # pylint: disable=broad-except
                LOG.warning("failed to refresh ontology from Fuseki (%s); falling back: %s", data_url, exc)
        if self._config.ontology_path:
            await asyncio.to_thread(self._evaluator.reload_from_path, self._config.ontology_path)
            self._evaluator.set_extra_facts(self._vc_extras)
            LOG.debug("ontology reloaded from local path %s", self._config.ontology_path)

    def _credential_hash_for_rows(self, rows: List[dict]) -> tuple[bytes, bool]:
        hash_bytes = bytes(32)
        revoked_detected = False
        for row in rows:
            canonical_entity = self._identity_hasher.canonical(row["Entity"])
            info = self._vc_metadata.get(canonical_entity)
            if not info:
                continue
            hash_bytes = info.get("hash_bytes", hash_bytes)
            revoked_detected = revoked_detected or bool(info.get("revoked", False))
            if hash_bytes != bytes(32) and not revoked_detected:
                break
        return hash_bytes, revoked_detected


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    vc_paths_env = os.environ.get("VC_PATHS", "")
    vc_paths = [entry.strip() for entry in vc_paths_env.split(",") if entry.strip()]
    cfg = NodeConfig(
        rpc_url=os.environ["RPC_URL"],
        contract_address=os.environ["CONTRACT_ADDRESS"],
        private_key=os.environ["ORACLE_PRIVATE_KEY"],
        aggregator_endpoint=os.environ["AGGREGATOR_ENDPOINT"],
        ontology_path=os.environ.get("ONTOLOGY_PATH", "ontologies/pharma-trust.owl"),
        policies_dir=os.environ.get("POLICIES_DIR", "policies"),
        stats_path=os.environ.get("STATS_PATH", "state/trust_stats.json"),
        identity_mode=os.environ.get("IDENTITY_MODE", "URI"),
        namespace=os.environ.get("NAMESPACE", "http://example.org/trust#"),
        did_network=os.environ.get("DID_ETHR_NETWORK", ""),
        allow_namespace_fallback=os.environ.get("DID_ALLOW_NAMES_FALLBACK", "true").lower() != "false",
        poll_interval=float(os.environ.get("POLL_INTERVAL", "5")),
        fuseki_base_url=os.environ.get("FUSEKI_BASE_URL", ""),
        fuseki_dataset=os.environ.get("FUSEKI_DATASET", "trustkb"),
        fuseki_user=os.environ.get("FUSEKI_USER", ""),
        fuseki_pass=os.environ.get("FUSEKI_PASS", ""),
        fuseki_accept=os.environ.get("FUSEKI_ACCEPT", "text/turtle"),
        fuseki_format=os.environ.get("FUSEKI_FORMAT", "turtle"),
        vc_paths=vc_paths,
        vc_property=os.environ.get("VC_PROPERTY", "hasGDPVC"),
    )
    node = OracleNode(cfg)
    asyncio.run(node.run())


if __name__ == "__main__":
    main()
