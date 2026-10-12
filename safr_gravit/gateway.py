"""
A SAFR-shaped runtime governance checkpoint with Gravit verification.

Follows the four components of SAFR v1.1 (MAS BuildFin.ai, 9 October 2026):
Governance Envelope -> Agent Identity -> Controls Repository -> Disposition
Engine (Deny / Escalate / Auto-Execute / Observe) -> Audit Log.

What Gravit adds, at the point SAFR leaves open:

* "The governance envelope should not be treated as self-verifying ... these
  fields should therefore be checked against records captured independently of
  the agent" (SAFR v1.1, p. 9). Each step of the agent-declared action trace is
  checked by the public Gravit Verifier against signed records from
  independent system operators (tool gateway, data provider, ...). Only steps
  that reach "Verified Fact" count as corroborated.
* "The log is the authoritative record, independent of any party with an
  interest" (p. 13). Audit Log entries are hash-chained and the export is
  signed by the institution's log key, so an auditor can verify integrity
  offline, without access to the platform (see audit.verify_export).
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from gravit_verifier import EpistemicState, EvidenceRecord, VerificationRequest, VerifierKernel
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.registry import VerifierRegistry

from .audit import AuditLog


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha3(obj: Any) -> str:
    return hashlib.sha3_256(canonical(obj)).hexdigest()


@dataclass
class Envelope:
    """SAFR Governance Envelope: action, action trace, context metadata (p. 9)."""

    envelope_id: str
    agent_id: str
    session_id: str
    mandate_id: str
    action: Dict[str, Any]                 # type, scope, parameters
    action_trace: List[Dict[str, Any]]     # steps: {"step_id", "kind", "detail"}
    context: Dict[str, Any] = field(default_factory=dict)
    agent_signature: str = ""              # Ed25519 by the agent over the envelope body

    def body(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "agent_signature"}


@dataclass
class Mandate:
    """An entry of the Controls Repository (machine-readable, versioned)."""

    mandate_id: str
    version: str
    allowed_actions: List[str]
    max_amount: float
    escalate_above: float
    allowed_counterparties: List[str]
    required_checks: List[str]             # trace steps that must be independently corroborated
    observe_new_counterparty: bool = True


class Gateway:
    def __init__(self, agents: Dict[str, bytes], mandates: Dict[str, Mandate], registry: VerifierRegistry,
                 bindings_dir: str, log: AuditLog) -> None:
        self.agents = agents
        self.mandates = mandates
        self.log = log
        self.kernel = VerifierKernel(registry)
        for b in load_bindings_from_dir(bindings_dir):
            self.kernel.load_binding(b)
        self.seen_counterparties: Dict[str, set] = {}

    # -- components -----------------------------------------------------------

    def identity(self, env: Envelope) -> Optional[str]:
        pub = self.agents.get(env.agent_id)
        if pub is None:
            return "agent not in registry"
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(env.agent_signature), canonical(env.body()))
        except (InvalidSignature, ValueError):
            return "envelope signature does not verify against the registered agent key"
        return None

    def corroborate(self, env: Envelope, step: Dict[str, Any], records: List[EvidenceRecord], now: str) -> Dict[str, Any]:
        """Is this agent-declared step confirmed by independent, signed system records?"""
        artifact = f"{env.envelope_id}/{step['step_id']}"
        step_hash = sha3({"envelope": env.envelope_id, "step": step})
        bound = [r for r in records if r.integrity_hash == step_hash]
        d = self.kernel.verify(VerificationRequest(
            artifact_id=artifact, claimed_state=EpistemicState.VERIFIED_FACT, evidence=bound,
            context={"evaluation_time": now, "freshness_max_age_seconds": 300, "high_impact": True}))
        return {"step_id": step["step_id"], "kind": step["kind"],
                "state": d.final_epistemic_state.value if d.final_epistemic_state else None,
                "status": d.status.value, "decision_id": d.decision_id,
                "records_bound": len(bound), "records_offered": len(records)}

    # -- the checkpoint -------------------------------------------------------

    def submit(self, env: Envelope, system_records: Dict[str, List[EvidenceRecord]], now: str) -> Dict[str, Any]:
        stages: List[Dict[str, Any]] = [{"stage": "received", "at": now}]
        entry: Dict[str, Any] = {"envelope": env.__dict__, "envelope_sha3": sha3(env.body())}

        problem = self.identity(env)
        stages.append({"stage": "agent_identity", "at": now, "ok": problem is None})
        if problem:
            return self._record(entry, stages, "Deny", ["SAFR-IDENTITY"], f"identity: {problem}", None)

        m = self.mandates.get(env.mandate_id)
        stages.append({"stage": "controls_repository", "at": now, "mandate_found": m is not None})
        if m is None:
            return self._record(entry, stages, "Deny", ["SAFR-MANDATE"], "no applicable mandate", None)
        mandate = {**m.__dict__, "mandate_sha3": sha3(m.__dict__)}

        a = env.action
        amount, cp = float(a.get("amount", 0)), a.get("counterparty")
        rules: List[str] = []
        if a.get("type") not in m.allowed_actions:
            return self._record(entry, stages, "Deny", ["CTRL-ACTION-TYPE"], f"action {a.get('type')!r} not in mandate", mandate)
        if amount > m.max_amount:
            return self._record(entry, stages, "Deny", ["CTRL-MAX-AMOUNT"], f"amount {amount} exceeds mandate limit {m.max_amount}", mandate)
        if cp not in m.allowed_counterparties:
            return self._record(entry, stages, "Deny", ["CTRL-COUNTERPARTY"], f"counterparty {cp!r} not allowed by mandate", mandate)
        rules += ["CTRL-ACTION-TYPE", "CTRL-MAX-AMOUNT", "CTRL-COUNTERPARTY"]

        checks = [s for s in env.action_trace if s["kind"] in m.required_checks]
        missing = sorted(set(m.required_checks) - {s["kind"] for s in checks})
        corroboration = [self.corroborate(env, s, system_records.get(s["step_id"], []), now) for s in checks]
        stages.append({"stage": "gravit_corroboration", "at": now, "steps": corroboration})
        rules.append("GRAVIT-TRACE-CORROBORATION")
        unverified = [c["step_id"] for c in corroboration if c["state"] != "Verified Fact"]
        if missing or unverified:
            why = (f"required checks missing from trace: {missing}; " if missing else "") + \
                  (f"trace steps not independently corroborated: {unverified}" if unverified else "")
            return self._record(entry, stages, "Escalate", rules, why.strip("; "), mandate, corroboration)

        if amount > m.escalate_above:
            rules.append("CTRL-ESCALATE-THRESHOLD")
            return self._record(entry, stages, "Escalate", rules, f"amount {amount} above autonomous threshold {m.escalate_above}", mandate, corroboration)

        known = self.seen_counterparties.setdefault(env.agent_id, set())
        first_time = cp not in known
        known.add(cp)
        if m.observe_new_counterparty and first_time:
            rules.append("CTRL-NOVELTY")
            return self._record(entry, stages, "Observe", rules, f"first payment by this agent to {cp!r}", mandate, corroboration)
        return self._record(entry, stages, "Auto-Execute", rules, "within mandate; every required check independently corroborated", mandate, corroboration)

    def _record(self, entry, stages, outcome, rules, basis, mandate, corroboration=None) -> Dict[str, Any]:
        stages.append({"stage": "disposition", "outcome": outcome})
        entry.update({"mandate": mandate, "outcome": outcome, "rules_applied": rules, "basis": basis,
                      "corroboration": corroboration, "stages": stages})
        return self.log.append(entry)
