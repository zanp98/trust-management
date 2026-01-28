#!/usr/bin/env python3
"""
Verify that a specific on-chain oracle report was signed by the claimed node.

Usage:
    python verify_oracle_report.py \\
        --subject 0xdb237a1e0bd7acf764a0295b586052d3944ade15e1146e16e596ed97795d7997 \\
        --decision true \\
        --score 9500 \\
        --flags 0 \\
        --as-of 1768907534 \\
        --policy-hash 0xf8fb86225ff3914c290bbed8314359b55ed8cd5b653f31ab040877ab203b33ec \\
        --credential-hash 0xac2c5789175018bbfb529451326330cd6e0cb9af89dd4cacdda8254ae927fae7 \\
        --signature 0x... \\
        --claimed-node 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
"""

import argparse
import json
from pathlib import Path
from eth_account.messages import encode_defunct
from web3 import Web3
import sys

# Import OracleReport from your codebase
sys.path.insert(0, str(Path(__file__).parent))
from oracle.common.report import OracleReport


def _parse_bool(raw: str) -> bool:
    value = str(raw or "").strip().lower()
    if value in ("1", "true", "yes", "y"):
        return True
    if value in ("0", "false", "no", "n"):
        return False
    raise ValueError(f"Invalid boolean value: {raw!r}")


def _parse_hex_bytes(raw: str, size: int) -> bytes:
    value = str(raw or "").strip()
    if value.startswith(("0x", "0X")):
        value = value[2:]
    data = bytes.fromhex(value) if value else b""
    if len(data) != size:
        raise ValueError(f"Expected {size} bytes, received {len(data)}")
    return data


def verify_oracle_report(
    subject: str,
    decision: str,
    score: int,
    flags: int,
    as_of: int,
    policy_hash: str,
    credential_hash: str,
    signature: str,
    claimed_node: str,
) -> bool:
    """
    Verify if a report was signed by the claimed node address.
    
    Returns True if signature is valid and recovered address matches claimed_node.
    """
    # Parse inputs
    subject_bytes = _parse_hex_bytes(subject, 32)
    decision_bool = _parse_bool(decision)
    policy_hash_bytes = _parse_hex_bytes(policy_hash, 32)
    credential_hash_bytes = _parse_hex_bytes(credential_hash, 32)
    signature_bytes = _parse_hex_bytes(signature, 65)  # secp256k1 signatures are 65 bytes
    claimed_node_lower = claimed_node.strip().lower()
    
    # Reconstruct the report
    report = OracleReport(
        subject=subject_bytes,
        decision=decision_bool,
        score=score,
        flags=flags,
        as_of=as_of,
        policy_hash=policy_hash_bytes,
        credential_hash=credential_hash_bytes,
    )
    
    # Get canonical JSON (this is what was signed)
    canonical_json = report.to_canonical_json()
    print(f"Canonical JSON that was signed:\n{canonical_json}\n")
    
    # Recover the signer from the signature
    w3 = Web3()
    signable = encode_defunct(text=canonical_json)
    try:
        recovered = w3.eth.account.recover_message(signable, signature=signature_bytes).lower()
    except Exception as e:
        print(f"❌ Failed to recover signature: {e}")
        return False
    
    print(f"Claimed node:  {claimed_node_lower}")
    print(f"Recovered sig: {recovered}")
    
    if recovered == claimed_node_lower:
        print("\n✅ SIGNATURE VALID: Report was signed by the claimed oracle node!")
        return True
    else:
        print("\n❌ SIGNATURE INVALID: Report was NOT signed by the claimed node!")
        print(f"   Signature was made by: {recovered}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Verify if an oracle report was signed by a specific node.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example (first report from your data):
  python verify_oracle_report.py \\
    --subject 0x903b3e50c643e6e58f8bce319e3bb5e090bc228119fbee8c5951e0b9694da28e \\
    --decision false \\
    --score 2382 \\
    --flags 2 \\
    --as-of 1768902951 \\
    --policy-hash 0x305744ff00e3141e930cdad84049d16b5a9d63af89e1d7dfaee6dacd1984fc14 \\
    --credential-hash 0xac2c5789175018bbfb529451326330cd6e0cb9af89dd4cacdda8254ae927fae7 \\
    --signature 0x<65-byte-hex-signature> \\
    --claimed-node 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

NOTE: You need the original signature from the oracle's submission logs.
        """,
    )
    parser.add_argument("--subject", required=True, help="32-byte subject hash (0x...)")
    parser.add_argument("--decision", required=True, help="Boolean decision (true/false)")
    parser.add_argument("--score", type=int, required=True, help="Score in basis points")
    parser.add_argument("--flags", type=int, required=True, help="Flags bitmask")
    parser.add_argument("--as-of", dest="as_of", type=int, required=True, help="Timestamp")
    parser.add_argument("--policy-hash", required=True, help="32-byte policy hash (0x...)")
    parser.add_argument("--credential-hash", required=True, help="32-byte credential hash (0x...)")
    parser.add_argument("--signature", required=True, help="65-byte signature (0x...)")
    parser.add_argument("--claimed-node", required=True, help="Node address (0x...)")
    
    args = parser.parse_args()
    
    is_valid = verify_oracle_report(
        subject=args.subject,
        decision=args.decision,
        score=args.score,
        flags=args.flags,
        as_of=args.as_of,
        policy_hash=args.policy_hash,
        credential_hash=args.credential_hash,
        signature=args.signature,
        claimed_node=args.claimed_node,
    )
    
    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
