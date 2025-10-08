# scripts/didkit_wrap.py
import json
import subprocess
import shutil
import asyncio
import inspect
import os
import didkit


def _run_async(maybe_coro):
    # If it's a coroutine, run it on a private event loop (robust across macOS/Python 3.10+)
    if inspect.isawaitable(maybe_coro):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(maybe_coro)
    return maybe_coro


class DIDKitAPI:
    """
    Wrapper that:
      - Prefers Python module (async/sync), auto-runs coroutines if needed
      - Falls back to DIDKit CLI if module isn't available or if DIDKIT_MODE=cli
    """
    def __init__(self):
        force_cli = os.getenv("DIDKIT_MODE", "").lower() == "cli"

        self.mode = "cli"  # default
        self.didkit = None

        if not force_cli:
            try:
                self.didkit = didkit
                self.mode = "py"
            except Exception:
                self.mode = "cli"

        if self.mode == "cli" and not shutil.which("didkit"):
            raise RuntimeError(
                "DIDKit not found. Install Python package `didkit` or the DIDKit CLI.\n"
                "To force CLI mode, set DIDKIT_MODE=cli (if CLI is installed)."
            )

    # ------------------ Python-mode helpers ------------------
    def _py_generate_ed25519_key(self):
        return _run_async(self.didkit.generate_ed25519_key())

    def _py_key_to_did(self, method: str, jwk: str):
        return _run_async(self.didkit.key_to_did(method, jwk))

    def _py_key_to_verification_method(self, method: str, jwk: str):
        return _run_async(self.didkit.key_to_verification_method(method, jwk))

    def _py_issue_credential(self, cred_json: str, proof_opts_json: str, jwk: str):
        return _run_async(self.didkit.issue_credential(cred_json, proof_opts_json, jwk))

    def _py_verify_credential(self, vc_json: str, verify_opts_json: str):
        res = _run_async(self.didkit.verify_credential(vc_json, verify_opts_json))
        # some builds return str, others dict; normalize to dict
        return json.loads(res) if isinstance(res, str) else res

    # ------------------ CLI-mode helpers ------------------
    def _cli(self, args, stdin=None) -> str:
        out = subprocess.check_output(args, input=stdin, stderr=subprocess.STDOUT)
        return out.decode().strip()

    # ------------------ Public API ------------------
    def generate_ed25519_key(self) -> str:
        if self.mode == "py":
            return self._py_generate_ed25519_key()
        return self._cli(["didkit", "generate-ed25519-key"])

    def key_to_did(self, method: str, jwk: str) -> str:
        if self.mode == "py":
            return self._py_key_to_did(method, jwk)
        return self._cli(["didkit", "key-to-did", method], stdin=jwk.encode())

    def key_to_verification_method(self, method: str, jwk: str) -> str:
        if self.mode == "py":
            return self._py_key_to_verification_method(method, jwk)
        return self._cli(["didkit", "key-to-verification-method", method], stdin=jwk.encode())

    def issue_credential(self, cred_json: str, proof_opts_json: str, jwk: str) -> str:
        if self.mode == "py":
            return self._py_issue_credential(cred_json, proof_opts_json, jwk)
        # CLI reads 3 JSON blobs from stdin in sequence
        payload = f"{cred_json}\n{proof_opts_json}\n{jwk}\n".encode()
        return self._cli(["didkit", "issue-credential", "-k", "-o", "-"], stdin=payload)

    def verify_credential(self, vc_json: str, verify_opts_json: str) -> dict:
        if self.mode == "py":
            return self._py_verify_credential(vc_json, verify_opts_json)
        payload = f"{vc_json}\n{verify_opts_json}\n".encode()
        out = self._cli(["didkit", "verify-credential", "-o", "-"], stdin=payload)
        return json.loads(out or "{}")
