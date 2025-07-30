
import json
from pathlib import Path
from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import XSD
import pandas as pd

TRUST = Namespace("http://example.org/trust#")

class TrustEvaluator:
    def __init__(self, owl_path: str):
        self.graph = Graph()
        self.graph.parse(owl_path, format="application/rdf+xml")

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
    for file in folder.glob("*.json"):
        with open(file, 'r') as f:
            policy = json.load(f)
            policies.append(policy)
    return policies

def get_all_entity_uris(graph, namespace: Namespace) -> list:
    subjects = set()
    for s, p, o in graph:
        if str(p).startswith(str(namespace)) and isinstance(o, Literal):
            subjects.add(str(s))
    return list(subjects)

def get_type_for_entity(graph: Graph, entity_uri: URIRef) -> str:
    for s, p, o in graph.triples((entity_uri, URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), None)):
        if str(o).startswith(str(TRUST)):
            return str(o).split("#")[-1]
    return None

if __name__ == "__main__":
    owl_file_path = "ontologies/pharma-trust.owl"
    evaluator = TrustEvaluator(owl_file_path)

    policies = load_policies_from_folder("policies")
    targets = get_all_entity_uris(evaluator.graph, TRUST)

    results = []
    for policy in policies:
        actor = policy["actor"].split("#")[-1]
        for target_uri in targets:
            entity = target_uri.split("#")[-1]
            if actor == entity:
                continue
            target_type = get_type_for_entity(evaluator.graph, URIRef(target_uri))
            if target_type in policy["trusts"]:
                trusted = evaluator.evaluate_trust(policy, target_type, target_uri)
                results.append({"Evaluator": actor, "Entity": entity, "Trusted": trusted})

    df = pd.DataFrame(results)
    df.to_csv("results/trust_evaluation_results.csv", index=False)
    print(df)
