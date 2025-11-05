import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from identity_utils import (
    IdentityHasher,
    credential_hash_hex,
    gather_vc_facts,
    load_vc,
    parse_vc_payload,
)


def test_load_vc_parses_descriptor():
    path = Path("tests/data/sample_vc.json")
    descriptor = load_vc(path)
    assert descriptor.subject_id == "http://example.org/trust#DHL"
    assert descriptor.issuer == "did:example:issuer"
    assert "GDPComplianceCredential" in descriptor.types
    assert descriptor.revoked is False
    assert descriptor.source_path == path


def test_parse_vc_payload_roundtrip():
    path = Path("tests/data/sample_vc.json")
    descriptor = load_vc(path)
    second = parse_vc_payload(descriptor.raw)
    assert descriptor.subject_id == second.subject_id
    assert descriptor.issuer == second.issuer


def test_credential_hash_is_deterministic():
    path = Path("tests/data/sample_vc.json")
    descriptor = load_vc(path)
    first = credential_hash_hex(descriptor)
    second = credential_hash_hex(load_vc(path))
    assert first == second
    assert first == "0xac2c5789175018bbfb529451326330cd6e0cb9af89dd4cacdda8254ae927fae7"


def test_gather_vc_facts_sets_extra_fact():
    hasher = IdentityHasher()
    extras, metadata = gather_vc_facts(["tests/data/sample_vc.json"], hasher, "hasGDPVC")
    canonical = hasher.canonical("http://example.org/trust#DHL")
    assert extras[canonical]["hasGDPVC"] == 1.0
    info = metadata[canonical]
    assert info["revoked"] is False
    assert info["hash_hex"] == "0xac2c5789175018bbfb529451326330cd6e0cb9af89dd4cacdda8254ae927fae7"
