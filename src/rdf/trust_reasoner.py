def is_entity_trusted(g, person_uri: str) -> bool:
    TRUST = Namespace("http://example.org/trust#")
    query = f"""
    ASK WHERE {{
        <{person_uri}> <{TRUST.hasCredential}> <{TRUST.VerifiedCredential}> .
    }}
    """
    return bool(g.query(query).askAnswer)
