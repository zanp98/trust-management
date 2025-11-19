# SPDX-License-Identifier: MIT
"""
Aggregator skeleton for the mini-DON.

Responsibilities:
  * accept signed oracle reports from multiple nodes
  * enforce quorum / aggregation logic (median score, majority flags)
  * submit a single `fulfillTrustReport` transaction to TrustGraph.sol
"""

from __future__ import annotations

import asyncio
import collections
import dataclasses
import json
import logging
import os
import threading
from typing import Any, Dict, List, Sequence, Tuple

from aiohttp import web
from eth_account.messages import encode_defunct
from web3 import Web3

from oracle.common.report import AggregatedReport, OracleReport, SignedOracleReport
from identity_utils import IdentityHasher, gather_vc_facts

LOG = logging.getLogger("oracle.aggregator")

if os.getenv("AGGREGATOR_DEBUGPY_PORT"):
    import debugpy

    host = os.getenv("AGGREGATOR_DEBUGPY_HOST", "0.0.0.0")
    port = int(os.getenv("AGGREGATOR_DEBUGPY_PORT", "8080"))
    LOG.info("debugpy listening on %s:%s; waiting for client...", host, port)
    debugpy.listen((host, port))
    # debugpy.wait_for_client() # Uncomment to block until debugger attaches

@dataclasses.dataclass
class AggregatorConfig:
    rpc_url: str
    contract_address: str
    private_key: str
    host: str = "0.0.0.0"
    port: int = 8080
    allowed_nodes: Sequence[str] = dataclasses.field(default_factory=list)
    quorum: int = 3
    poll_interval: float = 2.0
    identity_mode: str = "URI"
    namespace: str = "http://example.org/trust#"
    did_network: str = ""
    allow_namespace_fallback: bool = True
    vc_paths: Sequence[str] = dataclasses.field(default_factory=list)
    vc_property: str = "hasGDPVC"
    node_evaluator_map: Dict[str, str] = dataclasses.field(default_factory=dict)


class AggregationError(Exception):
    """Raised when reports cannot be aggregated due to validation issues."""


class CredentialValidationError(AggregationError):
    """Raised when VC hashes mismatch or are revoked."""


class AggregatorService:
    def __init__(self, config: AggregatorConfig):
        self._config = config
        self._w3 = Web3(Web3.HTTPProvider(config.rpc_url))
        if not self._w3.is_connected():
            raise RuntimeError(f"Unable to connect to RPC at {config.rpc_url}")
        with open("out/TrustGraph.sol/TrustGraph.json", "r", encoding="utf-8") as fh:
            artifact = json.load(fh)
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(config.contract_address),
            abi=artifact["abi"],
        )
        self._account = self._w3.eth.account.from_key(config.private_key)
        self._nonce_lock = threading.Lock()
        self._pending: Dict[bytes, List[SignedOracleReport]] = collections.defaultdict(list)
        self._allowed_nodes = {addr.lower() for addr in config.allowed_nodes}
        self._app = web.Application()
        self._app.add_routes([web.post("/reports", self._handle_report)])
        self._identity_hasher = IdentityHasher(
            identity_mode=config.identity_mode,
            namespace=config.namespace,
            did_network=config.did_network,
            allow_namespace_fallback=config.allow_namespace_fallback,
        )
        _, vc_metadata = gather_vc_facts(config.vc_paths, self._identity_hasher, config.vc_property)
        self._vc_lookup: Dict[bytes, Dict[str, Any]] = {}
        for canonical, info in vc_metadata.items():
            subject_hash = bytes(self._w3.keccak(text=canonical))
            self._vc_lookup[subject_hash] = info
        if self._vc_lookup:
            LOG.info("loaded %d verifiable credential(s) for validation", len(self._vc_lookup))
        self._node_evaluators = self._prepare_node_evaluators(config.node_evaluator_map)

    def _prepare_node_evaluators(self, mapping: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for raw_addr, label in mapping.items():
            addr = raw_addr.strip().lower()
            if not addr or not label:
                continue
            evaluator_hash = self._identity_hasher.hash_single(label)
            result[addr] = {"label": label, "hash": evaluator_hash}
        if result:
            LOG.info("configured %d node → evaluator mapping(s)", len(result))
        return result

    async def run(self) -> None:
        LOG.info("aggregator service started")
        runner = web.AppRunner(self._app)
        await runner.setup()
        site = web.TCPSite(runner, self._config.host, self._config.port)
        await site.start()
        LOG.info("listening on %s:%s", self._config.host, self._config.port)
        try:
            while True:
                await asyncio.sleep(self._config.poll_interval)
                await self._flush_ready_reports()
        finally:
            await runner.cleanup()

    async def _handle_report(self, request: web.Request) -> web.Response:
        try:
            payload = await request.json()
            request_id_hex = payload["request_id"]
            request_id = bytes.fromhex(request_id_hex[2:] if request_id_hex.startswith("0x") else request_id_hex)
            signed = SignedOracleReport.from_serialisable(payload["report"])
            self._verify_signature(signed)
            await self.submit_signed_report(request_id, signed)
            return web.json_response({"status": "accepted"})
        except (KeyError, ValueError, PermissionError) as err:
            LOG.warning("invalid submission: %s", err)
            return web.json_response({"error": str(err)}, status=400)

    async def submit_signed_report(self, request_id: bytes, signed_report: SignedOracleReport) -> None:
        LOG.info(
            "received signed report for %s from %s",
            request_id.hex(),
            signed_report.node_id,
        )
        bucket = self._pending[request_id]
        if any(existing.node_id == signed_report.node_id for existing in bucket):
            LOG.info("duplicate submission from %s for %s ignored", signed_report.node_id, request_id.hex())
            return
        bucket.append(signed_report)
        await self._record_individual_submission(request_id, signed_report)

    async def _flush_ready_reports(self) -> None:
        ready: List[bytes] = [
            request_id for request_id, reports in self._pending.items() if len(reports) >= self._config.quorum
        ]
        for request_id in ready:
            reports = self._pending.pop(request_id)
            try:
                aggregated = self.aggregate_reports(reports)
            except CredentialValidationError as err:
                LOG.warning("rejecting request %s due to credential validation failure: %s", request_id.hex(), err)
                continue
            except AggregationError as err:
                LOG.warning("unable to aggregate reports for %s: %s", request_id.hex(), err)
                continue
            await self.publish_report(request_id, aggregated)

    def aggregate_reports(self, reports: List[SignedOracleReport]) -> AggregatedReport:
        if not reports:
            raise AggregationError("no reports to aggregate")

        subjects = {r.report.subject for r in reports}
        if len(subjects) != 1:
            raise AggregationError("mismatched subjects in reports")

        policy_hashes = {r.report.policy_hash for r in reports}
        if len(policy_hashes) != 1:
            LOG.warning(
                "policy hash disagreement for %s – proceeding with first hash",
                reports[0].report.subject.hex(),
            )
        policy_hash = reports[0].report.policy_hash

        credential_hashes = {r.report.credential_hash for r in reports}
        if len(credential_hashes) > 1:
            raise CredentialValidationError("mismatched credential hashes in reports")
        credential_hash = credential_hashes.pop() if credential_hashes else bytes(32)

        # Majority vote for boolean decision
        positive = sum(1 for r in reports if r.report.decision)
        decision = positive * 2 >= len(reports)

        # Median for score
        scores = sorted(r.report.score for r in reports)
        mid = len(scores) // 2
        if len(scores) % 2 == 1:
            score = scores[mid]
        else:
            score = (scores[mid - 1] + scores[mid]) // 2

        # Bitwise majority for flags
        flags = 0
        max_bits = max((r.report.flags.bit_length() for r in reports), default=0)
        for bit in range(max_bits):
            mask = 1 << bit
            count = sum(1 for r in reports if r.report.flags & mask)
            if count * 2 >= len(reports):
                flags |= mask

        # Timestamp: use the latest as-of to ensure monotonicity
        as_of = max(r.report.as_of for r in reports)

        aggregated_report = OracleReport(
            subject=reports[0].report.subject,
            decision=decision,
            score=score,
            flags=flags,
            as_of=as_of,
            policy_hash=policy_hash,
            credential_hash=credential_hash,
        )
        expected = self._vc_lookup.get(aggregated_report.subject)
        if expected:
            if expected.get("hash_bytes") != credential_hash:
                raise CredentialValidationError("aggregated credential hash does not match local VC store")
            if expected.get("revoked", False):
                raise CredentialValidationError("aggregated credential hash corresponds to a revoked VC")
        node_ids = [r.node_id for r in reports]
        signatures = [r.signature for r in reports]
        return AggregatedReport(report=aggregated_report, node_ids=node_ids, signatures=signatures)

    async def publish_report(self, request_id: bytes, aggregated: AggregatedReport) -> None:
        LOG.info("publishing aggregated report for %s to TrustGraph.sol", request_id.hex())
        await asyncio.to_thread(self._send_transaction, request_id, aggregated)

    async def _record_individual_submission(self, request_id: bytes, signed: SignedOracleReport) -> None:
        node_id = signed.node_id.lower()
        evaluator = self._node_evaluators.get(node_id)
        if not evaluator:
            LOG.warning("no evaluator mapping configured for node %s; skipping on-chain record", node_id)
            return
        try:
            await asyncio.to_thread(
                self._send_submission_transaction,
                request_id,
                evaluator["hash"],
                signed,
                node_id,
            )
        except Exception as exc:  # pylint: disable=broad-except
            LOG.warning(
                "failed to record oracle submission for %s from %s: %s",
                request_id.hex(),
                node_id,
                exc,
            )

    def _send_transaction(self, request_id: bytes, aggregated: AggregatedReport) -> None:
        report = aggregated.report
        fn = self._contract.functions.fulfillTrustReport(
            request_id,
            (
                report.subject,
                report.decision,
                report.score,
                report.flags,
                report.as_of,
                report.policy_hash
            ),
        )
        tx_hash, receipt = self._send_contract_tx(fn)
        LOG.info("submitted fulfill tx %s", tx_hash.hex())
        if receipt.status != 1:
            LOG.error("transaction %s failed with status %s", tx_hash.hex(), receipt.status)

    def _send_submission_transaction(
        self,
        request_id: bytes,
        evaluator_hash: bytes,
        signed: SignedOracleReport,
        node_id: str,
    ) -> None:
        report = signed.report
        node_address = Web3.to_checksum_address(node_id)
        fn = self._contract.functions.recordOracleSubmission(
            request_id,
            evaluator_hash,
            (
                report.subject,
                report.decision,
                report.score,
                report.flags,
                report.as_of,
                report.policy_hash,
            ),
            report.credential_hash,
            node_address,
        )
        tx_hash, receipt = self._send_contract_tx(fn)
        if receipt.status != 1:
            LOG.error(
                "recordOracleSubmission tx %s failed with status %s",
                tx_hash.hex(),
                receipt.status,
            )
        else:
            LOG.info("recorded oracle submission for %s from %s via tx %s", request_id.hex(), node_id, tx_hash.hex())

    def _send_contract_tx(self, fn) -> Tuple[bytes, Any]:
        with self._nonce_lock:
            tx = fn.build_transaction(
                {
                    "from": self._account.address,
                    "nonce": self._w3.eth.get_transaction_count(self._account.address),
                    "gas": 500_000,
                    "gasPrice": self._w3.eth.gas_price,
                }
            )
            signed = self._account.sign_transaction(tx)
            tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash, receipt

    def _verify_signature(self, signed: SignedOracleReport) -> None:
        node_id = signed.node_id.lower()
        if self._allowed_nodes and node_id not in self._allowed_nodes:
            raise PermissionError(f"Node {node_id} is not authorised")
        digest = signed.report.to_canonical_json() # .encode("utf-8"))
        signable = encode_defunct(text=digest)
        recovered = self._w3.eth.account.recover_message(signable, signature=signed.signature).lower()
        if recovered != node_id:
            raise ValueError(f"Signature mismatch: recovered {recovered}, expected {node_id}")


def _parse_node_evaluator_map(raw: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for entry in raw.split(","):
        item = entry.strip()
        if not item or "=" not in item:
            continue
        addr, label = item.split("=", 1)
        mapping[addr.strip().lower()] = label.strip()
    return mapping

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    allowed = os.environ.get("ALLOWED_NODE_ADDRESSES", "")
    allowed_nodes = [addr.strip().lower() for addr in allowed.split(",") if addr.strip()]
    vc_paths_env = os.environ.get("VC_PATHS", "")
    vc_paths = [entry.strip() for entry in vc_paths_env.split(",") if entry.strip()]
    node_map = _parse_node_evaluator_map(os.environ.get("NODE_EVALUATOR_MAP", ""))
    cfg = AggregatorConfig(
        rpc_url=os.environ["RPC_URL"],
        contract_address=os.environ["CONTRACT_ADDRESS"],
        private_key=os.environ["AGGREGATOR_PRIVATE_KEY"],
        host=os.environ.get("AGGREGATOR_HOST", "0.0.0.0"),
        port=int(os.environ.get("AGGREGATOR_PORT", "8080")),
        allowed_nodes=allowed_nodes,
        quorum=int(os.environ.get("AGGREGATOR_QUORUM", "1")),
        identity_mode=os.environ.get("IDENTITY_MODE", "URI"),
        namespace=os.environ.get("NAMESPACE", "http://example.org/trust#"),
        did_network=os.environ.get("DID_ETHR_NETWORK", ""),
        allow_namespace_fallback=os.environ.get("DID_ALLOW_NAMES_FALLBACK", "true").lower() != "false",
        vc_paths=vc_paths,
        vc_property=os.environ.get("VC_PROPERTY", "hasGDPVC"),
        node_evaluator_map=node_map,
    )
    service = AggregatorService(cfg)
    asyncio.run(service.run())


if __name__ == "__main__":
    main()
