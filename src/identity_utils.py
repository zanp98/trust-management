import re
from dataclasses import dataclass
from typing import Iterable, List

from web3 import Web3


_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ETHR_DID_RE = re.compile(r"^did:ethr(?::([a-z0-9:-]+))?:(0x[a-fA-F0-9]{40})$", re.IGNORECASE)


class IdentityError(ValueError):
    """Raised when identity inputs are invalid or unsupported."""


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
