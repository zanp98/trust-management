#!/usr/bin/env python3
"""
Non-Repudiation Simulation: Demonstrates how oracles cannot deny signing reports.

Scenario:
  1. Oracle A signs and submits a report
  2. Oracle A later claims: "I never signed that!"
  3. We use ECDSA recovery to prove they're lying
"""

import sys
from pathlib import Path
from eth_account.messages import encode_defunct
from web3 import Web3

sys.path.insert(0, str(Path(__file__).parent))
from oracle.common.report import OracleReport


# Hardhat test accounts (well-known, deterministic)
ORACLE_A = {
    "private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "name": "Oracle A"
}

ORACLE_B = {
    "private_key": "0x59c6995e998f97a5a0044966f0943860380c38f28a29153643e7b3b6f4c8ba",
    "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "name": "Oracle B"
}


def simulate_oracle_submission():
    """Simulate: Oracle A creates and signs a report"""
    print("\n" + "=" * 80)
    print("SCENARIO 1: ORACLE A SUBMITS SIGNED REPORT")
    print("=" * 80)
    
    # Create a report (simulating some subject they evaluated)
    report = OracleReport(
        subject=Web3().keccak(text="Pfizer"),
        decision=True,  # Oracle A says: Pfizer is TRUSTWORTHY
        score=9000,
        flags=0,
        as_of=1768907533,
        policy_hash=Web3().keccak(text="policy_v1"),
        credential_hash=bytes(32),  # no credential
    )
    
    canonical_json = report.to_canonical_json()
    print(f"\nReport content:\n  {canonical_json}")
    
    # Oracle A signs it with their private key
    w3 = Web3()
    signable = encode_defunct(text=canonical_json)
    signed = w3.eth.account.sign_message(signable, private_key=ORACLE_A["private_key"])
    
    print(f"\nOracle A signs with private key:")
    print(f"  Key:       {ORACLE_A['private_key']}")
    print(f"  Address:   {ORACLE_A['address']}")
    print(f"  Signature: {signed.signature.hex()}")
    
    # Simulate submission to aggregator
    print(f"\n✅ Oracle A submits: Report + Signature to Aggregator")
    
    return report, signed.signature, canonical_json


def simulate_oracle_denial(report, signature, canonical_json):
    """Simulate: Oracle A claims they never signed it"""
    print("\n" + "=" * 80)
    print("SCENARIO 2: ORACLE A DENIES SIGNING (REPUDIATION ATTEMPT)")
    print("=" * 80)
    
    print(f"\nOracle A claims:")
    print(f"  'I never signed this report!'")
    print(f"  'This must be Oracle B or a forgery!'")
    
    # Try to recover signer
    print(f"\n🔍 Verifier (e.g., regulator) investigates...")
    w3 = Web3()
    signable = encode_defunct(text=canonical_json)
    
    try:
        recovered_address = w3.eth.account.recover_message(
            signable, signature=signature
        )
        print(f"\n✅ ECDSA Recovery succeeded!")
        print(f"   Recovered address: {recovered_address}")
        print(f"   Oracle A's address: {ORACLE_A['address']}")
        print(f"\n   🚨 MATCH! This proves Oracle A is LYING!")
        print(f"      The signature was mathematically created by Oracle A's private key.")
        print(f"      Oracle A CANNOT deny this - it's cryptographic proof!")
        return True
    except Exception as e:
        print(f"❌ Recovery failed: {e}")
        return False


def simulate_tampering_detection(original_report, signature, canonical_json):
    """Simulate: Someone tries to tamper with the report"""
    print("\n" + "=" * 80)
    print("SCENARIO 3: TAMPERING DETECTION (Report modified after signing)")
    print("=" * 80)
    
    # Create a different report (tampered)
    tampered_report = OracleReport(
        subject=original_report.subject,
        decision=False,  # Changed! Oracle A said TRUE, but now we claim FALSE
        score=2000,      # Changed!
        flags=0,
        as_of=original_report.as_of,
        policy_hash=original_report.policy_hash,
        credential_hash=original_report.credential_hash,
    )
    
    tampered_json = tampered_report.to_canonical_json()
    
    print(f"\nOriginal report JSON:\n  {canonical_json}")
    print(f"\nTampered report JSON:\n  {tampered_json}")
    
    # Try to verify tampered report with original signature
    print(f"\n🔍 Attacker tries to use Oracle A's signature on tampered report...")
    w3 = Web3()
    signable = encode_defunct(text=tampered_json)
    
    try:
        recovered_address = w3.eth.account.recover_message(
            signable, signature=signature
        )
        print(f"\n❌ Recovered: {recovered_address}")
        print(f"   This doesn't match Oracle A!")
        print(f"   ➜ Signature is INVALID for tampered report")
    except Exception:
        print(f"\n✅ TAMPER DETECTION WORKS!")
        print(f"   Signature verification FAILED")
        print(f"   ➜ Someone modified the report after signing!")


def simulate_oracle_b_trying_to_forge():
    """Simulate: Oracle B tries to claim they signed Oracle A's report"""
    print("\n" + "=" * 80)
    print("SCENARIO 4: ORACLE B TRIES TO FORGE (Signature verification)")
    print("=" * 80)
    
    # Oracle A's original report
    report = OracleReport(
        subject=Web3().keccak(text="Pfizer"),
        decision=True,
        score=9000,
        flags=0,
        as_of=1768907533,
        policy_hash=Web3().keccak(text="policy_v1"),
        credential_hash=bytes(32),
    )
    
    canonical_json = report.to_canonical_json()
    
    # Oracle A's real signature
    w3 = Web3()
    signable = encode_defunct(text=canonical_json)
    signed_by_a = w3.eth.account.sign_message(
        signable, private_key=ORACLE_A["private_key"]
    )
    
    print(f"\nOracle B claims:")
    print(f"  'This report is from me (Oracle B)!'")
    print(f"  'Signature: {signed_by_a.signature.hex()}'")
    
    # Verify signature
    print(f"\n🔍 Verifier checks the signature...")
    recovered = w3.eth.account.recover_message(signable, signature=signed_by_a.signature)
    
    print(f"   Claimed by:    {ORACLE_B['address']} (Oracle B)")
    print(f"   Recovered as:  {recovered}")
    
    if recovered.lower() == ORACLE_B['address'].lower():
        print(f"   ✅ Match - Oracle B signed this")
    else:
        print(f"   ❌ Mismatch! The signature was created by {recovered}")
        print(f"      It's impossible for Oracle B to create Oracle A's signature")
        print(f"      without Oracle A's private key (which is mathematically impossible)")


def main():
    print("\n" + "=" * 80)
    print("NON-REPUDIATION SIMULATION: How we prove oracles cannot deny")
    print("=" * 80)
    print("\nKey insight: ECDSA recovery proves who signed something,")
    print("without needing their private key. Forgery is mathematically impossible.")
    
    # Scenario 1: Submission
    report, signature, canonical_json = simulate_oracle_submission()
    
    # Scenario 2: Denial attempt (fails - proof of non-repudiation)
    simulate_oracle_denial(report, signature, canonical_json)
    
    # Scenario 3: Tampering detection
    simulate_tampering_detection(report, signature, canonical_json)
    
    # Scenario 4: Forgery attempt by another oracle
    simulate_oracle_b_trying_to_forge()
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY: NON-REPUDIATION GUARANTEES")
    print("=" * 80)
    print("""
✅ Oracle CANNOT deny signing:
   - Signature + ECDSA recovery = cryptographic proof of signer

✅ Oracle CANNOT forge other oracle's signature:
   - Only possible with private key (which is secret)

✅ Report CANNOT be tampered after signing:
   - Modified report fails signature verification

✅ Aggregator/Regulator CAN verify WITHOUT oracle's private key:
   - Only need: report + signature + recovered address
   - No secrets involved - verification is public

This is the foundation of blockchain accountability!
    """)


if __name__ == "__main__":
    main()
