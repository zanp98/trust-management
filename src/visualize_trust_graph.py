#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

from rdflib import Graph as RDFGraph, Namespace, URIRef

TRUST = Namespace("http://example.org/trust#")

# -----------------------------
# Helperji za branje ontologije
# -----------------------------
def load_types_from_owl(owl_path: Path) -> dict:
    """
    Vrne slovar: { "Pfizer": "Manufacturer", "DHL": "Transporter", ... }
    """
    g = RDFGraph()
    g.parse(str(owl_path), format="application/rdf+xml")

    types = {}
    for s, p, o in g.triples((None, URIRef(str(TRUST) + "hasAuditScore"), None)):
        # nič – samo to prisili rdflib, da prežveči literalne lastnosti :)
        pass

    # preberi rdf:type
    for s, p, o in g.triples((None, URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"), None)):
        s_str = str(s)
        o_str = str(o)
        if s_str.startswith(str(TRUST)) and o_str.startswith(str(TRUST)):
            name = s_str.split("#")[-1]
            rtype = o_str.split("#")[-1]
            # hočemo samo tipe, ki so pod Actor (Manufacturer/Distributor/...)
            if rtype in {"Manufacturer","Distributor","Transporter","Pharmacy","Regulator","RegulatoryAuthority","Actor"}:
                types[name] = rtype if rtype != "RegulatoryAuthority" else "Regulator"
    return types

# -----------------------------
# Vizualne nastavitve
# -----------------------------
NODE_COLOR_BY_TYPE = {
    "Manufacturer": "#1f77b4",  # modra
    "Distributor":  "#ff7f0e",  # oranžna
    "Transporter":  "#2ca02c",  # zelena
    "Pharmacy":     "#9467bd",  # vijolična
    "Regulator":    "#8c564b",  # rjava
    "Actor":        "#7f7f7f",  # siva (fallback)
}

NODE_SHAPE_BY_TYPE = {
    "Manufacturer": "s",  # square
    "Distributor":  "D",  # diamond
    "Transporter":  "^",  # triangle_up
    "Pharmacy":     "o",  # circle
    "Regulator":    "h",  # hexagon
    "Actor":        "o",
}

def pick_color_for_type(t: str) -> str:
    return NODE_COLOR_BY_TYPE.get(t, NODE_COLOR_BY_TYPE["Actor"])

def pick_shape_for_type(t: str) -> str:
    return NODE_SHAPE_BY_TYPE.get(t, NODE_SHAPE_BY_TYPE["Actor"])

# -----------------------------
# Risanje grafa
# -----------------------------
def draw_trust_graph(csv_path: Path, owl_path: Path, out_path: Path = None,
                     layout: str = "spring", show_labels: bool = True,
                     only_true: bool = False, hide_false_edges: bool = False):
    """
    Nariše graf zaupanja iz CSV (stolpci: Evaluator, Entity, Trusted) in OWL za tipe.
    """
    df = pd.read_csv(csv_path)
    if df["Trusted"].dtype != bool:
        df["Trusted"] = df["Trusted"].astype(str).str.lower().isin(["true","1","yes"])

    # če hočeš prikazati samo pozitivne relacije
    if only_true:
        df = df[df["Trusted"] == True]

    # Zgradi usmerjen graf
    G = nx.DiGraph()

    # tipi iz ontologije (za barve in oblike)
    types = load_types_from_owl(owl_path)

    # dodaj vsa vozlišča, ki se pojavijo
    all_nodes = set(df["Evaluator"].astype(str)).union(set(df["Entity"].astype(str)))
    for n in all_nodes:
        ntype = types.get(n, "Actor")
        G.add_node(n, ntype=ntype)

    # dodaj robove z atributi zaupanja
    for _, row in df.iterrows():
        ev = str(row["Evaluator"])
        en = str(row["Entity"])
        trusted = bool(row["Trusted"])
        # če ne želiš prikazovati False robov
        if hide_false_edges and not trusted:
            continue
        G.add_edge(ev, en, trusted=trusted)

    # postavitev
    if layout == "spring":
        pos = nx.spring_layout(G, seed=42, k=0.9)
    elif layout == "kamada_kawai":
        pos = nx.kamada_kawai_layout(G)
    elif layout == "circular":
        pos = nx.circular_layout(G)
    elif layout == "shell":
        pos = nx.shell_layout(G)
    else:
        pos = nx.spring_layout(G, seed=42)

    # skupine po tipu zaradi različnih oblik
    type_groups = {}
    for n, data in G.nodes(data=True):
        t = data.get("ntype", "Actor")
        type_groups.setdefault(t, []).append(n)

    plt.figure(figsize=(11, 8))

    # nariši vozlišča po skupinah (različne oblike)
    for t, nodes in type_groups.items():
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=nodes,
            node_shape=pick_shape_for_type(t),
            node_color=pick_color_for_type(t),
            edgecolors="white",
            linewidths=1.5,
            alpha=0.95,
            label=t
        )

    # nariši robove: True = zelena polna; False = rdeča črtkana
    true_edges  = [(u, v) for (u, v, d) in G.edges(data=True) if d.get("trusted", False)]
    false_edges = [(u, v) for (u, v, d) in G.edges(data=True) if not d.get("trusted", False)]

    nx.draw_networkx_edges(G, pos, edgelist=true_edges, arrows=True, width=2.2)
    nx.draw_networkx_edges(G, pos, edgelist=false_edges, arrows=True, width=1.6, style="dashed", edge_color="#d62728")

    # oznake vozlišč
    if show_labels:
        nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold")

    # legenda (po tipu)
    handles = []
    labels = []
    for t in type_groups.keys():
        handles.append(plt.Line2D([0], [0],
                                  marker=pick_shape_for_type(t),
                                  color="w",
                                  markerfacecolor=pick_color_for_type(t),
                                  markeredgecolor="white",
                                  markersize=10, linewidth=0))
        labels.append(t)
    # legenda za robove
    handles.append(plt.Line2D([0], [0], color="C0", lw=2.2, label="zaupa (True)"))
    labels.append("zaupa (True)")
    handles.append(plt.Line2D([0], [0], color="#d62728", lw=1.6, linestyle="--", label="ne zaupa (False)"))
    labels.append("ne zaupa (False)")

    plt.legend(handles, labels, loc="best", frameon=True)
    plt.axis("off")
    plt.tight_layout()

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path, dpi=200)
        print(f"[OK] Graf shranjen v: {out_path}")
    else:
        plt.show()
    plt.close()
    return G

def main():
    parser = argparse.ArgumentParser(description="Vizualizacija grafa zaupanja iz CSV in OWL.")
    parser.add_argument("--csv",  type=Path, required=True, help="Pot do results/trust_evaluation_results.csv")
    parser.add_argument("--owl",  type=Path, required=True, help="Pot do ontologies/pharma-trust.owl")
    parser.add_argument("--out",  type=Path, default=None, help="PNG izhod (npr. figures/trust-graph.png)")
    parser.add_argument("--layout", choices=["spring","kamada_kawai","circular","shell"], default="spring", help="Postavitev grafa")
    parser.add_argument("--labels", action="store_true", help="Prikaži oznake vozlišč")
    parser.add_argument("--only-true", action="store_true", help="Prikaži samo pozitivne relacije")
    parser.add_argument("--hide-false-edges", action="store_true", help="Skrij negativne robove")
    args = parser.parse_args()

    draw_trust_graph(
        csv_path=args.csv,
        owl_path=args.owl,
        out_path=args.out,
        layout=args.layout,
        show_labels=args.labels,
        only_true=args.only_true,
        hide_false_edges=args.hide_false_edges
    )

if __name__ == "__main__":
    main()
