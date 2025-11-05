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
from typing import Dict, List, Sequence

from aiohttp import web
from eth_account.messages import encode_defunct
from web3 import Web3

from oracle.common.report import AggregatedReport, OracleReport, SignedOracleReport

LOG = logging.getLogger("oracle.aggregator")

if os.getenv("AGGREGATOR_DEBUGPY_PORT"):
    import debugpy

    host = os.getenv("AGGREGATOR_DEBUGPY_HOST", "0.0.0.0")
    port = int(os.getenv("AGGREGATOR_DEBUGPY_PORT", "8080"))
    LOG.info("debugpy listening on %s:%s; waiting for client...", host, port)
    debugpy.listen((host, port))
    debugpy.wait_for_client()

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
        self._pending: Dict[bytes, List[SignedOracleReport]] = collections.defaultdict(list)
        self._allowed_nodes = {addr.lower() for addr in config.allowed_nodes}
        self._app = web.Application()
        self._app.add_routes([web.post("/reports", self._handle_report)])

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

    async def _flush_ready_reports(self) -> None:
        ready: List[bytes] = [
            request_id for request_id, reports in self._pending.items() if len(reports) >= self._config.quorum
        ]
        for request_id in ready:
            reports = self._pending.pop(request_id)
            aggregated = self.aggregate_reports(reports)
            await self.publish_report(request_id, aggregated)

    def aggregate_reports(self, reports: List[SignedOracleReport]) -> AggregatedReport:
        if not reports:
            raise ValueError("no reports to aggregate")

        subjects = {r.report.subject for r in reports}
        if len(subjects) != 1:
            raise ValueError("mismatched subjects in reports")

        policy_hashes = {r.report.policy_hash for r in reports}
        if len(policy_hashes) != 1:
            raise ValueError("mismatched policy hashes in reports")
        policy_hash = policy_hashes.pop()

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
        )
        node_ids = [r.node_id for r in reports]
        signatures = [r.signature for r in reports]
        return AggregatedReport(report=aggregated_report, node_ids=node_ids, signatures=signatures)

    async def publish_report(self, request_id: bytes, aggregated: AggregatedReport) -> None:
        LOG.info("publishing aggregated report for %s to TrustGraph.sol", request_id.hex())
        await asyncio.to_thread(self._send_transaction, request_id, aggregated)

    def _send_transaction(self, request_id: bytes, aggregated: AggregatedReport) -> None:
        report = aggregated.report
        tx = self._contract.functions.fulfillTrustReport(
            request_id,
            (
                report.subject,
                report.decision,
                report.score,
                report.flags,
                report.as_of,
                report.policy_hash
            ),
        ).build_transaction(
            {
                "from": self._account.address,
                "nonce": self._w3.eth.get_transaction_count(self._account.address),
                "gas": 500_000,
                "gasPrice": self._w3.eth.gas_price,
            }
        )
        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        LOG.info("submitted fulfill tx %s", tx_hash.hex())
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            LOG.error("transaction %s failed with status %s", tx_hash.hex(), receipt.status)

    def _verify_signature(self, signed: SignedOracleReport) -> None:
        node_id = signed.node_id.lower()
        if self._allowed_nodes and node_id not in self._allowed_nodes:
            raise PermissionError(f"Node {node_id} is not authorised")
        digest = signed.report.to_canonical_json() # .encode("utf-8"))
        signable = encode_defunct(text=digest)
        recovered = self._w3.eth.account.recover_message(signable, signature=signed.signature).lower()
        if recovered != node_id:
            raise ValueError(f"Signature mismatch: recovered {recovered}, expected {node_id}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    allowed = os.environ.get("ALLOWED_NODE_ADDRESSES", "")
    allowed_nodes = [addr.strip().lower() for addr in allowed.split(",") if addr.strip()]
    cfg = AggregatorConfig(
        rpc_url=os.environ["RPC_URL"],
        contract_address=os.environ["CONTRACT_ADDRESS"],
        private_key=os.environ["AGGREGATOR_PRIVATE_KEY"],
        host=os.environ.get("AGGREGATOR_HOST", "0.0.0.0"),
        port=int(os.environ.get("AGGREGATOR_PORT", "8080")),
        allowed_nodes=allowed_nodes,
        quorum=int(os.environ.get("AGGREGATOR_QUORUM", "3")),
    )
    service = AggregatorService(cfg)
    asyncio.run(service.run())


if __name__ == "__main__":
    main()
