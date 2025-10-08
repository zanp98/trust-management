import json
from pathlib import Path
from trust_evaluator_ext import TrustEvaluatorExt


def load_policies(folder: str):
    arr = []
    for p in Path(folder).glob("*.json"):
        arr.append(json.loads(p.read_text(encoding="utf-8")))
    return arr


if __name__ == "__main__":
    owl = "ontologies/pharma-trust.owl"
    policies = load_policies("policies")

    eva = TrustEvaluatorExt(owl_path=owl, stats_path="state/trust_stats.json",
                            gamma=0.25, obs_scale=9.0)

    df0 = eva.run_full_evaluation(policies, export_csv="results/trust_eval_hybrid_round0.csv")
    print(df0)

    # primer online posodobitve (po potrebi prilagodi)
    pfizer = "http://example.org/trust#Pfizer"
    dhl = "http://example.org/trust#DHL"
    eva.update_from_observation(
        policy=[p for p in policies if p["actor"] == pfizer][0],
        actor_type="Transporter",
        evaluator_uri=pfizer,
        target_uri=dhl,
        observed={"hasDeliveryPunctuality": 0.96, "hasTempViolationRate": 0.02}
    )

    df1 = eva.run_full_evaluation(policies, export_csv="results/trust_eval_hybrid_round1.csv")
    print(df1)
