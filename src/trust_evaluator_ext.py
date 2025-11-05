import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import pandas as pd
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF

TRUST = Namespace("http://example.org/trust#")


def _as_float(value: Literal) -> Optional[float]:
    try:
        return float(value.toPython())
    except Exception:
        return None


def _is_boolean_property(prop: str) -> bool:
    return prop in {"hasLicense", "hasGMP"}


def _desirability(rule: Dict, prop: str, x: Optional[float]) -> Optional[float]:
    if x is None:
        return None
    cond = rule.get(prop)
    if isinstance(cond, dict):
        if "gte" in cond:
            t = float(cond["gte"])
            if t >= 1.0:
                return 1.0 if x >= t else 0.0
            return max(0.0, min(1.0, (x - t) / max(1e-9, (1.0 - t))))
        if "lte" in cond:
            t = float(cond["lte"])
            if t <= 0.0:
                return 1.0 if x <= t else 0.0
            return max(0.0, min(1.0, (t - x) / max(1e-9, t)))
    elif isinstance(cond, bool):
        return 1.0 if (bool(x) == cond) else 0.0
    return None


class TrustStatsStore:
    """
    Shranjuje posteriorje Beta(α, β) za (evaluator, entity, property).
    EWMA posodobitev:
      alpha <- (1-γ)*alpha + γ*(1 + s*obs_scale)
      beta  <- (1-γ)*beta  + γ*(1 + (1-s)*obs_scale)
    """
    def __init__(self, path: str, gamma: float = 0.2, obs_scale: float = 9.0):
        self.path = Path(path)
        self.gamma = float(gamma)
        self.obs_scale = float(obs_scale)
        self._store = {}
        if self.path.exists():
            try:
                self._store = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._store = {}

    def _key(self, evaluator_uri: str, entity_uri: str, prop: str) -> str:
        return f"{evaluator_uri}||{entity_uri}||{prop}"

    def get(self, evaluator_uri: str, entity_uri: str, prop: str) -> Tuple[float, float]:
        rec = self._store.get(self._key(evaluator_uri, entity_uri, prop))
        if not rec:
            return (1.0, 1.0)
        return float(rec["alpha"]), float(rec["beta"])

    def seed(self, evaluator_uri: str, entity_uri: str, prop: str, s0: float):
        k = self._key(evaluator_uri, entity_uri, prop)
        if k in self._store:
            return
        alpha0 = 1.0 + s0 * self.obs_scale
        beta0 = 1.0 + (1.0 - s0) * self.obs_scale
        self._store[k] = {"alpha": alpha0, "beta": beta0}

    def update(self, evaluator_uri: str, entity_uri: str, prop: str, s: float):
        alpha, beta = self.get(evaluator_uri, entity_uri, prop)
        g = self.gamma
        a_new = (1 - g) * alpha + g * (1.0 + s * self.obs_scale)
        b_new = (1 - g) * beta + g * (1.0 + (1.0 - s) * self.obs_scale)
        self._store[self._key(evaluator_uri, entity_uri, prop)] = {"alpha": a_new, "beta": b_new}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._store, indent=2), encoding="utf-8")


class TrustEvaluatorExt:
    """
    Hibridni evaluator:
      - deterministična presoja JSON pravil,
      - verjetnostni score z Beta-EWMA,
      - kombinirana odločitev (OR; možno spremeniti).
    """
    def __init__(self, owl_path: str | None, stats_path: str = "state/trust_stats.json",
                 gamma: float = 0.2, obs_scale: float = 9.0):
        self._owl_path = owl_path
        self.g = Graph()
        if owl_path:
            self.g.parse(owl_path, format="application/rdf+xml")
        self.stats = TrustStatsStore(stats_path, gamma=gamma, obs_scale=obs_scale)
        self._extra_facts: Dict[str, Dict[str, float]] = {}

    def reload_from_path(self, path: str | None = None, rdf_format: str = "application/rdf+xml") -> None:
        src = path or self._owl_path
        if not src:
            raise ValueError("No ontology path provided for reload")
        g = Graph()
        g.parse(src, format=rdf_format)
        self.g = g
        if path:
            self._owl_path = path

    def reload_from_bytes(self, data: bytes | str, rdf_format: str = "turtle") -> None:
        g = Graph()
        payload = data if isinstance(data, str) else data.decode("utf-8")
        g.parse(data=payload, format=rdf_format)
        self.g = g
        # Do not reset _owl_path; bytes-based reload is ephemeral.

    def set_extra_facts(self, extras: Optional[Dict[str, Dict[str, float]]]) -> None:
        self._extra_facts = extras or {}

    # ------ ontology utilities ------
    def get_all_entity_uris(self) -> List[str]:
        subjects = set()
        for s, p, o in self.g:
            if str(p).startswith(str(TRUST)) and isinstance(o, Literal):
                subjects.add(str(s))
        return list(subjects)

    def get_type_for_entity(self, entity_uri: str) -> Optional[str]:
        for _, _, o in self.g.triples((URIRef(entity_uri), RDF.type, None)):
            if str(o).startswith(str(TRUST)):
                return str(o).split("#")[-1]
        return None

    def get_value(self, entity_uri: str, prop: str) -> Optional[float]:
        extra = self._extra_facts.get(entity_uri, {}).get(prop)
        if extra is not None:
            return extra
        val = self.g.value(subject=URIRef(entity_uri), predicate=TRUST[prop])
        if val is None:
            return None
        if _is_boolean_property(prop):
            return 1.0 if bool(val.toPython()) else 0.0
        return _as_float(val)

    # ------ deterministic ------
    def eval_deterministic(self, policy: Dict, actor_type: str, target_uri: str) -> bool:
        conditions = policy.get("trusts", {}).get(actor_type, {})
        for prop, cond in conditions.items():
            x = self.get_value(target_uri, prop)
            if x is None:
                return False
            if isinstance(cond, dict):
                for op, t in cond.items():
                    t = float(t)
                    if op == "gte" and x < t:
                        return False
                    if op == "lte" and x > t:
                        return False
            elif isinstance(cond, bool):
                if bool(x) != cond:
                    return False
        return True

    # ------ probabilistic ------
    def _weights_for(self, policy: Dict, actor_type: str) -> Dict[str, float]:
        conds = policy.get("trusts", {}).get(actor_type, {})
        ws = policy.get("_weights", {})
        active = {p: float(ws.get(p, 1.0)) for p in conds.keys()}
        s = sum(active.values()) or 1.0
        return {k: v / s for k, v in active.items()}

    def _seed_from_ontology(self, evaluator_uri: str, target_uri: str, conds: Dict):
        for prop in conds.keys():
            x = self.get_value(target_uri, prop)
            s0 = _desirability(conds, prop, x)
            if s0 is not None:
                self.stats.seed(evaluator_uri, target_uri, prop, s0)

    def eval_probabilistic(self, policy: Dict, actor_type: str, target_uri: str):
        evaluator_uri = policy["actor"]
        conds = policy.get("trusts", {}).get(actor_type, {})
        if not conds:
            return (0.0, False)
        self._seed_from_ontology(evaluator_uri, target_uri, conds)
        ws = self._weights_for(policy, actor_type)
        parts = []
        for prop in conds.keys():
            alpha, beta = self.stats.get(evaluator_uri, target_uri, prop)
            mean = alpha / (alpha + beta)
            parts.append(ws[prop] * mean)
        score = sum(parts) if parts else 0.0
        thr = float(policy.get("prob_threshold", 0.7))
        return (score, score >= thr)

    # ------ online updates ------
    def update_from_observation(self, policy: Dict, actor_type: str,
                                evaluator_uri: str, target_uri: str,
                                observed: Dict[str, float]):
        conds = policy.get("trusts", {}).get(actor_type, {})
        for prop in conds.keys():
            if prop not in observed:
                continue
            s = _desirability(conds, prop, float(observed[prop]))
            if s is not None:
                self.stats.update(evaluator_uri, target_uri, prop, s)
        self.stats.save()

    # ------ run & export ------
    def run_full_evaluation(self, policies: List[Dict], export_csv: str = "results/trust_eval_hybrid.csv") -> pd.DataFrame:
        targets = self.get_all_entity_uris()
        rows = []
        for policy in policies:
            evaluator_uri = policy["actor"]
            evaluator = evaluator_uri.split("#")[-1]
            for target_uri in targets:
                entity = target_uri.split("#")[-1]
                if evaluator_uri.endswith(f"#{entity}"):
                    continue
                ttype = self.get_type_for_entity(target_uri)
                if not ttype or ttype not in policy.get("trusts", {}):
                    continue
                det_dec = self.eval_deterministic(policy, ttype, target_uri)
                prob_score, prob_dec = self.eval_probabilistic(policy, ttype, target_uri)
                combined = det_dec or prob_dec
                rows.append({
                    "Evaluator": evaluator,
                    "Entity": entity,
                    "Type": ttype,
                    "Deterministic": det_dec,
                    "ProbScore": round(prob_score, 4),
                    "ProbDecision": prob_dec,
                    "CombinedDecision": combined
                })
        df = pd.DataFrame(rows)
        Path(export_csv).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(export_csv, index=False)
        return df
