# SPDX-License-Identifier: MIT
"""
Shared report models used by oracle nodes and the aggregator.

These dataclasses intentionally mirror the `OracleReport` struct and related
storage in `TrustGraph.sol`. They provide helpers for canonical JSON encoding
so signatures are deterministic across different runtimes.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List


def _encode_hex(value: bytes) -> str:
    return "0x" + value.hex()


def _decode_hex(value: str, size: int) -> bytes:
    if value.startswith("0x") or value.startswith("0X"):
        value = value[2:]
    data = bytes.fromhex(value)
    if len(data) != size:
        raise ValueError(f"Expected {size} bytes, received {len(data)}")
    return data


@dataclasses.dataclass(frozen=True)
class OracleReport:
    subject: bytes  # 32-byte hash (keccak of DID/URI)
    decision: bool
    score: int
    flags: int
    as_of: int
    policy_hash: bytes  # 32-byte hash
    credential_hash: bytes  # 32-byte hash

    def to_serialisable(self) -> Dict[str, Any]:
        return {
            "subject": _encode_hex(self.subject),
            "decision": bool(self.decision),
            "score": int(self.score),
            "flags": int(self.flags),
            "as_of": int(self.as_of),
            "policy_hash": _encode_hex(self.policy_hash),
            "credential_hash": _encode_hex(self.credential_hash),
        }

    def to_canonical_json(self) -> str:
        """Stable JSON encoding used for digital signatures."""
        return json.dumps(self.to_serialisable(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_serialisable(cls, data: Dict[str, Any]) -> "OracleReport":
        return cls(
            subject=_decode_hex(data["subject"], 32),
            decision=bool(data["decision"]),
            score=int(data["score"]),
            flags=int(data["flags"]),
            as_of=int(data["as_of"]),
            policy_hash=_decode_hex(data["policy_hash"], 32),
            credential_hash=_decode_hex(data.get("credential_hash", "0x" + "00" * 32), 32),
        )


@dataclasses.dataclass(frozen=True)
class SignedOracleReport:
    report: OracleReport
    node_id: str          # e.g. Ethereum address (lowercase)
    signature: bytes      # secp256k1 signature over canonical JSON

    def to_serialisable(self) -> Dict[str, Any]:
        return {
            "report": self.report.to_serialisable(),
            "node_id": self.node_id,
            "signature": _encode_hex(self.signature),
        }

    @classmethod
    def from_serialisable(cls, data: Dict[str, Any]) -> "SignedOracleReport":
        return cls(
            report=OracleReport.from_serialisable(data["report"]),
            node_id=str(data["node_id"]).lower(),
            signature=bytes.fromhex(data["signature"][2:] if data["signature"].startswith("0x") else data["signature"]),
        )


@dataclasses.dataclass(frozen=True)
class AggregatedReport:
    report: OracleReport
    node_ids: List[str]
    signatures: List[bytes]

    def to_serialisable(self) -> Dict[str, Any]:
        return {
            "report": self.report.to_serialisable(),
            "node_ids": self.node_ids,
            "signatures": [_encode_hex(sig) for sig in self.signatures],
        }
