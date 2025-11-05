import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from web3 import Web3


_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ETHR_DID_RE = re.compile(r"^did:ethr(?::([a-z0-9:-]+))?:(0x[a-fA-F0-9]{40})$", re.IGNORECASE)


class IdentityError(ValueError):
    """Raised when identity inputs are invalid or unsupported."""


class CredentialParseError(ValueError):
    """Raised when VC payloads are missing required fields."""


def _normalise_namespace(namespace: str) -> str:
    namespace = (namespace or "").strip()
    if not namespace:
        return ""
    return namespace.rstrip("#/")


def _to_uri(label: str, namespace: str) -> str:
    label = str(label or "").strip()
    if not label:
        raise IdentityError("Empty identifier label supplied for URI mode")
    if label.startswith(("http://", "https://")):
        return label
    base = _normalise_namespace(namespace)
    if not base:
        return label
    return f"{base}#{label}"


def _normalise_ethr_did(raw: str, default_network: str = "") -> str:
    value = str(raw or "").strip()
    if not value:
        raise IdentityError("Empty identifier supplied for DID mode")

    match = _ETHR_DID_RE.match(value)
    if match:
        network, address = match.groups()
        checksum = Web3.to_checksum_address(address)
        if network:
            return f"did:ethr:{network}:{checksum}"
        return f"did:ethr:{checksum}"

    if _ETH_ADDRESS_RE.match(value):
        checksum = Web3.to_checksum_address(value)
        network = (default_network or "").strip()
        if network:
            return f"did:ethr:{network}:{checksum}"
        return f"did:ethr:{checksum}"

    raise IdentityError(
        f"Unsupported DID/identifier '{raw}'. Expected did:ethr or Ethereum address."
    )


@dataclass
class IdentityHasher:
    """Produces canonical identifiers and keccak hashes based on the configured mode."""

    identity_mode: str = "URI"
    namespace: str = ""
    did_network: str = ""
    allow_namespace_fallback: bool = True
    debug: bool = False

    def __post_init__(self):
        self.identity_mode = (self.identity_mode or "URI").strip().upper()
        self.namespace = self.namespace or ""
        self.did_network = (self.did_network or "").strip()
        self._w3 = Web3()

    def canonical(self, raw: str) -> str:
        if self.identity_mode == "DID":
            try:
                value = _normalise_ethr_did(raw, self.did_network)
                if self.debug:
                    print(f"[identity] Normalised {raw!r} -> {value} (did:ethr)")
                return value
            except IdentityError as err:
                if self.allow_namespace_fallback and self.namespace:
                    fallback = _to_uri(raw, self.namespace)
                    if self.debug:
                        print(
                            "[identity] Falling back to namespace mapping for "
                            f"{raw!r} -> {fallback}"
                        )
                    return fallback
                raise err

        value = _to_uri(raw, self.namespace)
        if self.debug:
            print(f"[identity] Normalised {raw!r} -> {value} (URI)")
        return value

    def hash_single(self, raw: str) -> bytes:
        canonical_value = self.canonical(raw)
        digest = bytes(self._w3.keccak(text=canonical_value))
        if self.debug:
            print(f"[identity] Hashed {canonical_value} -> {digest.hex()}")
        return digest

    def hash_many(self, values: Iterable[str]) -> List[bytes]:
        return [self.hash_single(v) for v in values]


@dataclass(frozen=True)
class CredentialDescriptor:
    subject_id: str
    issuer: str
    types: Sequence[str]
    revoked: bool
    raw: Dict[str, Any]
    source_path: Path | None = None


def _coerce_types(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def parse_vc_payload(payload: Dict[str, Any], source_path: Path | None = None) -> CredentialDescriptor:
    try:
        subject = payload["credentialSubject"]
    except KeyError as err:
        raise CredentialParseError("VC missing credentialSubject") from err
    if isinstance(subject, dict):
        subject_id = subject.get("id") or subject.get("subject", {}).get("id")
    else:
        raise CredentialParseError("credentialSubject must be an object")
    if not subject_id:
        raise CredentialParseError("credentialSubject.id missing in VC")

    issuer = payload.get("issuer")
    if isinstance(issuer, dict):
        issuer = issuer.get("id")
    if not issuer:
        raise CredentialParseError("issuer missing in VC")

    types = _coerce_types(payload.get("type"))
    status = payload.get("credentialStatus", {})
    revoked = bool(status.get("revoked", False))

    return CredentialDescriptor(
        subject_id=str(subject_id),
        issuer=str(issuer),
        types=types,
        revoked=revoked,
        raw=payload,
        source_path=source_path,
    )


def load_vc(path: str | Path) -> CredentialDescriptor:
    vc_path = Path(path)
    payload = json.loads(vc_path.read_text(encoding="utf-8"))
    return parse_vc_payload(payload, vc_path)


def credential_hash(descriptor: CredentialDescriptor) -> bytes:
    canonical = json.dumps(descriptor.raw, sort_keys=True, separators=(",", ":"))
    w3 = Web3()
    return bytes(w3.keccak(text=canonical))


def credential_hash_hex(descriptor: CredentialDescriptor) -> str:
    return "0x" + credential_hash(descriptor).hex()


def iter_vc_descriptors(paths: Iterable[str]) -> Iterable[CredentialDescriptor]:
    seen: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        path = Path(raw).expanduser()
        if path.is_dir():
            for candidate in sorted(path.glob("*.json*")):
                key = str(candidate.resolve())
                if key in seen:
                    continue
                seen.add(key)
                yield load_vc(candidate)
        elif path.exists():
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            yield load_vc(path)


def gather_vc_facts(
    paths: Iterable[str],
    hasher: IdentityHasher,
    property_name: str,
) -> Tuple[Dict[str, Dict[str, float]], Dict[str, Dict[str, Any]]]:
    extras: Dict[str, Dict[str, float]] = {}
    metadata: Dict[str, Dict[str, Any]] = {}
    for descriptor in iter_vc_descriptors(paths):
        canonical = hasher.canonical(descriptor.subject_id)
        info = {
            "hash_bytes": credential_hash(descriptor),
            "hash_hex": credential_hash_hex(descriptor),
            "path": str(descriptor.source_path) if descriptor.source_path else "",
            "revoked": descriptor.revoked,
            "issuer": descriptor.issuer,
            "types": list(descriptor.types),
        }
        metadata[canonical] = info
        if not descriptor.revoked:
            extras.setdefault(canonical, {})[property_name] = 1.0
    return extras, metadata
