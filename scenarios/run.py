#!/usr/bin/env python3
"""
Eight agentic-payment scenarios through the SAFR checkpoint, then an offline
audit of the exported log (and of a tampered copy).

Deterministic (fixed timestamps, test keys): writes results/audit-export.json
and results/summary.json; CI regenerates them and fails on any byte change.
"""

import base64
import copy
import json
from pathlib import Path

from safr_gravit.audit import AuditLog, verify_export
from safr_gravit.gateway import Envelope, Gateway, Mandate, canonical, sha3
from safr_gravit.testkeys import key, pub, registry, system_record

ROOT = Path(__file__).resolve().parent.parent
BINDINGS = ROOT / ".deps" / "verifier" / "bindings"
NOW = "2026-10-12T09:00:00Z"
INSTITUTION = "Example Bank Ltd"

MANDATE = Mandate(
    mandate_id="treasury-payments-v3", version="3.0", allowed_actions=["payment"], max_amount=100_000,
    escalate_above=50_000, allowed_counterparties=["SUPPLIER-0042", "SUPPLIER-0077"],
    required_checks=["kyc_check", "sanctions_screening"])


def envelope(eid, amount, cp, agent="treasury-agent-7", trace=None, sign_as=None):
    trace = trace if trace is not None else [
        {"step_id": "s1", "kind": "invoice_lookup", "detail": f"invoice for {cp}"},
        {"step_id": "s2", "kind": "kyc_check", "detail": f"KYC status of {cp}"},
        {"step_id": "s3", "kind": "sanctions_screening", "detail": f"screen {cp}"},
    ]
    env = Envelope(envelope_id=eid, agent_id=agent, session_id="sess-2026-10-12-01", mandate_id=MANDATE.mandate_id,
                   action={"type": "payment", "amount": amount, "currency": "SGD", "counterparty": cp},
                   action_trace=trace, context={"account": "OPS-SGD-01"})
    env.agent_signature = base64.b64encode(key(sign_as or agent).sign(canonical(env.body()))).decode()
    return env


def records(env, producers_by_kind):
    """System records confirming the trace steps (bound to the exact step content)."""
    out = {}
    for step in env.action_trace:
        art, h = f"{env.envelope_id}/{step['step_id']}", sha3({"envelope": env.envelope_id, "step": step})
        out[step["step_id"]] = [system_record(p, art, h, NOW) for p in producers_by_kind.get(step["kind"], [])]
    return out


BOTH = {"kyc_check": ["kyc-provider", "bank-tool-gateway"], "sanctions_screening": ["sanctions-screening", "bank-tool-gateway"]}


def scenarios():
    e = envelope("env-001", 12_000, "SUPPLIER-0042")
    yield "First payment to a supplier, checks corroborated", e, records(e, BOTH)
    e = envelope("env-002", 8_000, "SUPPLIER-0042")
    yield "Repeat payment, checks corroborated", e, records(e, BOTH)
    e = envelope("env-003", 250_000, "SUPPLIER-0042")
    yield "Amount above the mandate limit", e, records(e, BOTH)
    e = envelope("env-004", 5_000, "SUPPLIER-0042", agent="unknown-agent-99")
    yield "Agent not in the registry", e, records(e, BOTH)
    e = envelope("env-005", 5_000, "SUPPLIER-0042")
    rec = records(e, BOTH)
    e.action["amount"] = 95_000  # altered after the agent signed the envelope
    yield "Envelope altered after signing", e, rec
    e = envelope("env-006", 7_000, "SUPPLIER-0077")
    yield "Trace claims checks no system recorded (fabricated trace)", e, {}
    e = envelope("env-007", 7_000, "SUPPLIER-0077")
    rec = records(e, {"kyc_check": ["kyc-provider"], "sanctions_screening": ["sanctions-screening"]})
    yield "Each check confirmed by only one source", e, rec
    e = envelope("env-008", 60_000, "SUPPLIER-0042")
    yield "Above the autonomous threshold, checks corroborated", e, records(e, BOTH)


def main() -> int:
    log = AuditLog()
    gw = Gateway({"treasury-agent-7": pub("treasury-agent-7")}, {MANDATE.mandate_id: MANDATE}, registry(), str(BINDINGS), log)
    rows = []
    for name, env, recs in scenarios():
        entry = gw.submit(env, recs, NOW)
        b = entry["body"]
        rows.append({"scenario": name, "envelope": env.envelope_id, "outcome": b["outcome"], "basis": b["basis"]})
        print(f"{b['outcome']:13} {name:58} {b['basis'][:80]}")
    export = log.export(key("example-bank-audit-log"), INSTITUTION, NOW)
    audit = verify_export(export, pub("example-bank-audit-log"))
    tampered = copy.deepcopy(export)
    tampered["entries"][5]["body"]["outcome"] = "Auto-Execute"  # rewrite one decision after the fact
    audit_tampered = verify_export(tampered, pub("example-bank-audit-log"))
    print(f"\nauditor, offline: {audit}\nauditor, tampered copy: {audit_tampered}")
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    (out / "audit-export.json").write_text(json.dumps(export, indent=1, sort_keys=True) + "\n")
    (out / "summary.json").write_text(json.dumps({"scenarios": rows, "auditor_offline_check": audit,
                                                  "auditor_check_of_tampered_copy": audit_tampered},
                                                 indent=1, sort_keys=True) + "\n")
    return 0 if audit["ok"] and not audit_tampered["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
