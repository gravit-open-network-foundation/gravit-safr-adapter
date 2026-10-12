"""SAFR Audit Log: append-only, hash-chained, exported with an Ed25519 signature
so that an auditor can verify integrity without access to the platform."""

import base64
import hashlib
import json
from typing import Any, Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class AuditLog:
    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def append(self, body: Dict[str, Any]) -> Dict[str, Any]:
        e = {"seq": len(self.entries), "prev_hash": self.entries[-1]["entry_hash"] if self.entries else GENESIS,
             "body": body}
        e["entry_hash"] = hashlib.sha256(canonical(e)).hexdigest()
        self.entries.append(e)
        return e

    def export(self, log_key: Ed25519PrivateKey, institution: str, exported_at: str) -> Dict[str, Any]:
        head = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        statement = {"institution": institution, "exported_at": exported_at, "entries": len(self.entries), "head": head}
        return {"statement": statement, "signature": base64.b64encode(log_key.sign(canonical(statement))).decode(),
                "entries": self.entries}


def verify_export(export: Dict[str, Any], institution_public_key: bytes) -> Dict[str, Any]:
    """Offline check by an auditor: signature over the statement, every hash link,
    and that the signed head and count match the entries. No platform access needed."""
    st = export["statement"]
    try:
        Ed25519PublicKey.from_public_bytes(institution_public_key).verify(
            base64.b64decode(export["signature"]), canonical(st))
    except (InvalidSignature, ValueError):
        return {"ok": False, "reason": "export signature does not verify"}
    prev = GENESIS
    for i, e in enumerate(export["entries"]):
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if e["seq"] != i or e["prev_hash"] != prev or hashlib.sha256(canonical(body)).hexdigest() != e["entry_hash"]:
            return {"ok": False, "reason": f"chain broken at entry {i}"}
        prev = e["entry_hash"]
    if prev != st["head"] or len(export["entries"]) != st["entries"]:
        return {"ok": False, "reason": "entries do not match the signed head"}
    return {"ok": True, "entries": st["entries"], "head": st["head"]}
