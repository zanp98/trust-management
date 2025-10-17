"""Economic collusion simulation and guardrail checks.

Maps to `THREAT_MODEL.md` §3.1 (Economic attack → collusion) by asserting:
  * each entity's trust decision is endorsed by at least `min_unique_evaluators`
  * no single evaluator dominates more than `max_single_share` of the votes

When run as a script it prints a JSON summary and exits with non-zero status
if alerts are present and `--fail-on-alert` is supplied.
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

TruthValue = Tuple[str, bool]


@dataclass
class EntityAssessment:
    entity: str
    unique_evaluators: int
    total_votes: int
    dominant_evaluator: str | None
    dominant_share: float
    alerts: List[str]


def _normalise_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "t"}


def load_votes(csv_path: Path) -> Dict[str, List[TruthValue]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required_cols = {"Evaluator", "Entity", "CombinedDecision"}
        missing = required_cols - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{csv_path} missing required columns: {sorted(missing)}")
        votes: Dict[str, List[TruthValue]] = {}
        for row in reader:
            entity = row["Entity"].strip()
            evaluator = row["Evaluator"].strip()
            decision = _normalise_bool(row["CombinedDecision"])
            votes.setdefault(entity, []).append((evaluator, decision))
    return votes


def analyse_collusion(
    votes: Dict[str, List[TruthValue]],
    min_unique_evaluators: int = 2,
    max_single_share: float = 0.6,
) -> List[EntityAssessment]:
    assessments: List[EntityAssessment] = []
    for entity, entries in votes.items():
        evaluator_hist: Dict[str, int] = {}
        for evaluator, _ in entries:
            evaluator_hist[evaluator] = evaluator_hist.get(evaluator, 0) + 1

        total_votes = len(entries)
        unique_evaluators = len(evaluator_hist)
        dominant_evaluator, dominant_count = max(
            evaluator_hist.items(), key=lambda item: item[1]
        )
        dominant_share = dominant_count / max(1, total_votes)

        alerts: List[str] = []
        if unique_evaluators < min_unique_evaluators:
            alerts.append(
                f"insufficient_unique:{unique_evaluators}/{min_unique_evaluators}"
            )
        if dominant_share > max_single_share:
            alerts.append(
                f"dominant_share:{dominant_share:.2f}>{max_single_share:.2f}"
            )

        assessments.append(
            EntityAssessment(
                entity=entity,
                unique_evaluators=unique_evaluators,
                total_votes=total_votes,
                dominant_evaluator=dominant_evaluator,
                dominant_share=dominant_share,
                alerts=alerts,
            )
        )
    return assessments


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect potential evaluator collusion in trust decisions."
    )
    parser.add_argument("--csv", type=Path, required=True, help="Path to evaluation CSV.")
    parser.add_argument(
        "--min-unique",
        type=int,
        default=2,
        help="Minimum distinct evaluators required per entity.",
    )
    parser.add_argument(
        "--max-share",
        type=float,
        default=0.6,
        help="Maximum allowed share of votes by a single evaluator.",
    )
    parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="Exit with status 1 if any alerts are detected.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON summary instead of table.",
    )
    return parser


def run(
    csv_path: Path,
    min_unique: int,
    max_share: float,
    fail_on_alert: bool,
    as_json: bool,
) -> int:
    votes = load_votes(csv_path)
    assessments = analyse_collusion(
        votes,
        min_unique_evaluators=min_unique,
        max_single_share=max_share,
    )
    alerts = [a for a in assessments if a.alerts]
    if as_json:
        payload = [asdict(a) for a in assessments]
        print(json.dumps(payload, indent=2))
    else:
        print(f"Analysed {len(assessments)} entities from {csv_path}")
        for assessment in assessments:
            alert_flag = "⚠️" if assessment.alerts else "✅"
            reasons = ", ".join(assessment.alerts) if assessment.alerts else "-"
            print(
                f"{alert_flag} {assessment.entity}: "
                f"{assessment.unique_evaluators} evaluators, "
                f"dominant {assessment.dominant_evaluator} ({assessment.dominant_share:.2f}), "
                f"alerts: {reasons}"
            )
    if fail_on_alert and alerts:
        return 1
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return run(
        csv_path=args.csv,
        min_unique=args.min_unique,
        max_share=args.max_share,
        fail_on_alert=args.fail_on_alert,
        as_json=args.json,
    )


if __name__ == "__main__":
    raise SystemExit(main())
