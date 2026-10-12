"""TEST keys only (derived from public seeds): agents, system-record operators,
the operator registry with its 3-of-5 test trust root, and the institution's
audit-log key. Never use outside this demonstration."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from gravit_verifier import EvidenceRecord
from gravit_verifier.registry import (TrustRoot, VerifierRegistry, key_id_for, registry_signing_message,
                                      signing_message)

# system-record producers (independent of the agent) -> operator legal entity
OPERATORS = {
    "bank-tool-gateway": "Example Bank Ltd (tool-call gateway)",
    "kyc-provider": "Example KYC Services Pte Ltd",
    "sanctions-screening": "Example Screening Services AG",
}


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"gravit-safr-test:" + name.encode()).digest())


def pub(name: str) -> bytes:
    return key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _doc(o) -> bytes:
    return (json.dumps(o, indent=1, sort_keys=True) + "\n").encode()


def registry() -> VerifierRegistry:
    roots = [f"root-{i}" for i in range(1, 6)]
    tr = TrustRoot.from_bytes(_doc({"trust_root_version": 1, "threshold": 3, "root_keys": [
        {"key_id": key_id_for(pub(r)), "public_key": base64.b64encode(pub(r)).decode()} for r in roots]}))
    reg = _doc({"registry_version": 1, "verifiers": [
        {"key_id": key_id_for(pub(n)), "public_key": base64.b64encode(pub(n)).decode(), "operator": op, "revoked": False}
        for n, op in OPERATORS.items()]})
    msg = registry_signing_message(reg)
    sigs = "".join(f"{key_id_for(pub(r))} {base64.b64encode(key(r).sign(msg)).decode()}\n" for r in roots[:3])
    return VerifierRegistry.from_bytes(reg, sigs, tr)


def system_record(producer: str, artifact_id: str, step_hash: str, timestamp: str, theta: float = 0.95) -> EvidenceRecord:
    """A signed, system-generated record confirming one step of an action trace."""
    r = EvidenceRecord(record_id=f"{producer}:{artifact_id}", theta=theta, result=True, verifier_id=producer,
                       timestamp=timestamp, provenance=OPERATORS.get(producer, "unregistered"),
                       integrity_hash=step_hash, key_id=key_id_for(pub(producer)))
    r.signature = base64.b64encode(key(producer).sign(signing_message(artifact_id, r))).decode()
    return r
