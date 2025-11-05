import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

from dotenv import load_dotenv

from identity_utils import (
    IdentityHasher,
    gather_vc_facts,
)
from trust_evaluator_ext import TrustEvaluatorExt


def load_policies(folder: str):
    policies = []
    for policy_path in Path(folder).glob("*.json"):
        policies.append(json.loads(policy_path.read_text(encoding="utf-8")))
    return policies


def _normalise_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "t"}


def _attach_vc_metadata(
    df,
    hasher: IdentityHasher,
    vc_metadata: Dict[str, Dict[str, Any]],
):
    if not vc_metadata or df.empty:
        return df
    df = df.copy()
    canonical_entities = df["Entity"].map(hasher.canonical)
    df["CredentialHash"] = canonical_entities.map(
        lambda key: vc_metadata.get(key, {}).get("hash_hex", "")
    )
    df["VCPath"] = canonical_entities.map(lambda key: vc_metadata.get(key, {}).get("path", ""))
    df["VCRevoked"] = canonical_entities.map(lambda key: vc_metadata.get(key, {}).get("revoked", False))
    return df


def main(argv=None):
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run hybrid trust evaluation.")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging during evaluation.",
    )
    parser.add_argument(
        "--policies-dir",
        default="policies",
        help="Path to the policies directory (default: policies).",
    )
    parser.add_argument(
        "--ontology",
        default="ontologies/pharma-trust.owl",
        help="Path to the ontology file.",
    )
    parser.add_argument(
        "--round0-csv",
        default="results/trust_eval_hybrid_round0.csv",
        help="Output CSV path for round 0.",
    )
    parser.add_argument(
        "--round1-csv",
        default="results/trust_eval_hybrid_round1.csv",
        help="Output CSV path for round 1.",
    )
    parser.add_argument(
        "--vc",
        dest="vc_paths",
        action="append",
        default=[],
        help="Path to a verifiable credential file or directory (repeatable).",
    )
    parser.add_argument(
        "--vc-property",
        default="hasGDPVC",
        help="Ontology property to toggle when a VC is present (default: hasGDPVC).",
    )
    parser.add_argument(
        "--identity-mode",
        default=os.getenv("IDENTITY_MODE", "URI"),
        help="Identity mode for canonicalisation (default from IDENTITY_MODE env).",
    )
    parser.add_argument(
        "--namespace",
        default=os.getenv("NAMESPACE", "http://example.org/trust#"),
        help="Namespace used for URI identity mode (default from NAMESPACE env).",
    )
    parser.add_argument(
        "--did-network",
        default=os.getenv("DID_ETHR_NETWORK", ""),
        help="did:ethr network hint (default from DID_ETHR_NETWORK env).",
    )
    parser.add_argument(
        "--allow-did-fallback",
        default=os.getenv("DID_ALLOW_NAMES_FALLBACK", "true"),
        help="Allow namespace fallback for DID mode (default from env).",
    )
    args = parser.parse_args(argv)

    policies = load_policies(args.policies_dir)
    if args.debug:
        print(f"[eval] Loaded {len(policies)} policies from {args.policies_dir}")

    allow_fallback = _normalise_bool(args.allow_did_fallback)
    hasher = IdentityHasher(
        identity_mode=args.identity_mode,
        namespace=args.namespace,
        did_network=args.did_network,
        allow_namespace_fallback=allow_fallback,
    )

    vc_overrides, vc_metadata = gather_vc_facts(args.vc_paths, hasher, args.vc_property)
    if args.debug and vc_metadata:
        print(f"[eval] Loaded {len(vc_metadata)} verifiable credential(s)")

    evaluator = TrustEvaluatorExt(
        owl_path=args.ontology,
        stats_path="state/trust_stats.json",
        gamma=0.25,
        obs_scale=9.0,
    )
    evaluator.set_extra_facts(vc_overrides)

    df0 = evaluator.run_full_evaluation(policies, export_csv=args.round0_csv)
    df0 = _attach_vc_metadata(df0, hasher, vc_metadata)
    df0.to_csv(args.round0_csv, index=False)
    if args.debug:
        print(f"[eval] Round 0 written to {args.round0_csv}")
    print(df0)

    # Example online update (adjust or remove as needed)
    pfizer = "http://example.org/trust#Pfizer"
    dhl = "http://example.org/trust#DHL"
    evaluator.update_from_observation(
        policy=[p for p in policies if p["actor"] == pfizer][0],
        actor_type="Transporter",
        evaluator_uri=pfizer,
        target_uri=dhl,
        observed={"hasDeliveryPunctuality": 0.96, "hasTempViolationRate": 0.02},
    )
    if args.debug:
        print("[eval] Applied sample online observation for Pfizer → DHL")

    df1 = evaluator.run_full_evaluation(policies, export_csv=args.round1_csv)
    df1 = _attach_vc_metadata(df1, hasher, vc_metadata)
    df1.to_csv(args.round1_csv, index=False)
    if args.debug:
        print(f"[eval] Round 1 written to {args.round1_csv}")
    print(df1)


if __name__ == "__main__":
    main()
