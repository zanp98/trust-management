import argparse
import json
from pathlib import Path

from trust_evaluator_ext import TrustEvaluatorExt


def load_policies(folder: str):
    policies = []
    for policy_path in Path(folder).glob("*.json"):
        policies.append(json.loads(policy_path.read_text(encoding="utf-8")))
    return policies


def main(argv=None):
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
    args = parser.parse_args(argv)

    policies = load_policies(args.policies_dir)
    if args.debug:
        print(f"[eval] Loaded {len(policies)} policies from {args.policies_dir}")

    evaluator = TrustEvaluatorExt(
        owl_path=args.ontology,
        stats_path="state/trust_stats.json",
        gamma=0.25,
        obs_scale=9.0,
    )

    df0 = evaluator.run_full_evaluation(policies, export_csv=args.round0_csv)
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
    if args.debug:
        print(f"[eval] Round 1 written to {args.round1_csv}")
    print(df1)


if __name__ == "__main__":
    main()
