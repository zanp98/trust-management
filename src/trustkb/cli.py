import click

from .client import FusekiClient
from .hashing import hash_default_graph
from .queries import entity_triples, list_classes, manufacturers
from .updates import delete_entity, insert_manufacturer, link_trusted_partner


@click.group()
def cli():
    """Utilities for interacting with the trust knowledge base (Fuseki)."""


@cli.command()
def classes():
    """List ontology classes."""
    client = FusekiClient()
    result = client.select(list_classes())
    for binding in result["results"]["bindings"]:
        print(binding["class"]["value"])


@cli.command("list-manufacturers")
def list_manufacturers_cmd():
    """List known pharm:Manufacturer instances."""
    client = FusekiClient()
    result = client.select(manufacturers())
    for binding in result["results"]["bindings"]:
        print(binding["m"]["value"])


@cli.command("add-manufacturer")
@click.argument("name")
@click.option("--score", type=float, default=None, help="Optional trust score")
def add_manufacturer_cmd(name: str, score: float | None):
    """Insert a pharm:Manufacturer with an optional trust score."""
    client = FusekiClient()
    client.update(insert_manufacturer(name, score))
    click.echo(f"Added Manufacturer pharm:{name} (score={score})")


@cli.command()
@click.argument("src")
@click.argument("dst")
def trust(src: str, dst: str):
    """Link src pharm:trustedPartner dst."""
    client = FusekiClient()
    client.update(link_trusted_partner(src, dst))
    click.echo(f"Linked pharm:{src} -> pharm:{dst} via pharm:trustedPartner")


@cli.command("rm")
@click.argument("name")
def delete_entity_cmd(name: str):
    """Delete all triples for pharm:<name>."""
    client = FusekiClient()
    client.update(delete_entity(name))
    click.echo(f"Deleted all triples for pharm:{name}")


@cli.command()
@click.argument("entity_iri")
def dump(entity_iri: str):
    """Advise how to dump an entity's triples (construct query)."""
    _ = entity_triples(entity_iri)  # kept for clarity; consider using direct HTTP calls.
    click.echo(
        "Use curl with the CONSTRUCT query to fetch Turtle:\n"
        "curl -G $(python -c 'from src.trustkb.config import FusekiConfig; print(FusekiConfig().query_url)') "
        "--data-urlencode \"query=$(python - <<'PY'\n"
        "from src.trustkb.queries import entity_triples\n"
        f"print(entity_triples('{entity_iri}'))\n"
        "PY\n"
        ")\" -H 'Accept: text/turtle'"
    )


@cli.command("graph-hash")
def graph_hash():
    """Return SHA-256 hash of the Fuseki default graph."""
    checksum = hash_default_graph()
    click.echo(checksum)


if __name__ == "__main__":
    cli()
