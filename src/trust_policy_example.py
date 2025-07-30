
import json
from pathlib import Path
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import XSD


TRUST = Namespace("http://example.org/trust#")


class TrustEvaluator:
    def __init__(self, rdf_data: dict):
        self.graph = Graph()
        self._populate_graph(rdf_data)

    def _populate_graph(self, data):
        for entity_uri, props in data.items():
            subj = URIRef(entity_uri)
            for prop, val in props.items():
                pred = TRUST[prop]
                if isinstance(val, float):
                    lit = Literal(val, datatype=XSD.float)
                elif isinstance(val, bool):
                    lit = Literal(val, datatype=XSD.boolean)
                elif isinstance(val, int):
                    lit = Literal(val, datatype=XSD.integer)
                else:
                    lit = Literal(val)
                self.graph.add((subj, pred, lit))

    def evaluate_trust(self, policy: dict, actor_type: str, target_uri: str) -> bool:
        conditions = policy.get('trusts', {}).get(actor_type, {})
        for prop, rule in conditions.items():
            prop_uri = TRUST[prop]
            value = self.graph.value(subject=URIRef(target_uri), predicate=prop_uri)

            if value is None:
                return False

            if isinstance(rule, dict):
                for op, threshold in rule.items():
                    val = float(value.toPython())
                    if op == "gte" and val < threshold:
                        return False
                    if op == "lte" and val > threshold:
                        return False
            elif isinstance(rule, bool):
                if str(value.toPython()).lower() != str(rule).lower():
                    return False

        return True


def load_policies_from_folder(folder_path: str) -> list:
    policies = []
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"The folder {folder_path} does not exist or is not a directory.")
    for file in folder.glob("*.json"):
        with open(file, 'r') as f:
            policy = json.load(f)
            policies.append(policy)
    return policies


def example_data():
    return {
        "http://example.org/trust#DHL": {
            "hasDeliveryPunctuality": 0.88,
            "hasTempViolationRate": 0.03,
            "hasLicense": True
        },
        "http://example.org/trust#MediPlus": {
            "hasPrescriptionComplianceRate": 0.91,
            "hasLicense": True
        },
        "http://example.org/trust#EuroLogistics": {
            "hasDeliveryDelayRate": 0.08,
            "hasLicense": True
        },
        "http://example.org/trust#EMA": {
            "hasIssuedCertifications": 34,
            "hasJurisdictionLevel": "global"
        }
    }


if __name__ == "__main__":
    data = example_data()
    evaluator = TrustEvaluator(data)

    policies = load_policies_from_folder("policies")
    results = []

    for policy in policies:
        actor = policy["actor"].split("#")[-1]
        for target_uri in data:
            entity = target_uri.split("#")[-1]
            for actor_type in policy["trusts"]:
                if evaluator.evaluate_trust(policy, actor_type, target_uri):
                    results.append({"Evaluator": actor, "Entity": entity, "Trusted": True})
                else:
                    results.append({"Evaluator": actor, "Entity": entity, "Trusted": False})

    import pandas as pd
    df = pd.DataFrame(results)
    df.to_csv("trust_evaluation_results.csv", index=False)
    print(df)
