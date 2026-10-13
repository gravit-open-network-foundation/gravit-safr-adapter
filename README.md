# SAFR × Gravit — verifiable runtime governance for agentic finance

A working reference adapter between **SAFR** (*Safeguards for Agentic Finance at Runtime*,
v1.1, 9 October 2026, developed by the financial industry under MAS's BuildFin.ai initiative)
and the public **[Gravit Verifier](https://github.com/gravit-open-network-foundation/verifier)**.

SAFR defines *what* must hold at runtime: a Governance Envelope, Agent Identity, a Controls
Repository, a Disposition Engine with four outcomes, and a tamper-evident Audit Log. This adapter
shows *one way* to make two of its hardest requirements independently verifiable:

1. **The envelope is not self-verifying.** SAFR (p. 9): action details and trace supplied by the
   agent "should therefore be checked against records captured independently of the agent".
   Here every required step of the agent's action trace (e.g. KYC check, sanctions screening) is
   checked by the Gravit Verifier against **signed records from independent system operators**,
   bound to the exact step content. A step counts as done only if it reaches *Verified Fact*:
   at least two independent registered operators, fresh, with provenance.
2. **The log is the authoritative record.** SAFR (p. 13): "independent of any party with an
   interest". Audit Log entries are hash-chained and the export is signed with the
   institution's key, so an **auditor verifies it offline**, without access to the platform.

## Run

```bash
make setup PYTHON=python3.12   # installs the Gravit Verifier at tag v0.6.0
make run                       # 10 scenarios + offline audit -> results/
make test
```

| # | Scenario | SAFR outcome |
|---|---|---|
| 1 | First payment to a supplier, checks corroborated | **Observe** (novel counterparty) |
| 2 | Repeat payment, checks corroborated | **Auto-Execute** |
| 3 | Amount above the mandate limit | **Deny** |
| 4 | Agent not in the registry | **Deny** (identity) |
| 5 | Envelope altered after the agent signed it | **Deny** (identity) |
| 6 | Trace claims checks that no system recorded (fabricated trace) | **Escalate** |
| 7 | Each check confirmed by only one source | **Escalate** |
| 8 | Above the autonomous threshold, checks corroborated | **Escalate** |
| 9 | KYC provider signs a failed check (`result=false`) | **Escalate** (check failed) |
| 10 | Checks signed without a verdict (`result=null`) | **Escalate** |

Scenarios 9 and 10 were added after Iman Schrock (EMILIA Protocol) showed that with verifier v0.5.0 a
signed `false` or `null` still led to Auto-Execute: the verifier ignored the signed result.
Fixed in verifier v0.6.0 (`CANON-RES-012`, `docs/signed-result.md` there). Escalating a failed
check rather than denying it is a configurable policy choice.

Then: the exported log verifies offline; a copy in which one decision was rewritten afterwards,
or one entry deleted, fails. CI regenerates `results/` and fails on any byte change.

## Mapping to SAFR v1.1

| SAFR element (page) | Requirement | In this adapter |
|---|---|---|
| Governance Envelope (p. 9) | action, action trace, context metadata; bound to agent, session, mandate; protected against alteration | `Envelope`, signed by the registered agent key; any change after signing → Deny |
| Envelope not self-verifying (p. 9) | check against records captured independently of the agent | Gravit Verifier over signed system records; ≥ 2 independent operators per required step |
| Agent Identity (p. 10) | verify against the registry before any other evaluation; failure rejected and logged | registry lookup + signature check first; Deny with reason, logged |
| Controls Repository (pp. 10–11) | configurable rulebook; mandates in machine-readable form | `Mandate` (machine-readable), logged with its SHA3-256 |
| Disposition Engine (pp. 11–12) | Deny / Escalate / Auto-Execute / Observe, specific reason recorded | all four, deterministic, rules applied and basis recorded |
| Audit Log (pp. 12–13) | tamper-evident, append-only; envelope, mandate, outcome, rules, basis, time per stage | hash-chained entries with all of these; signed export; offline verification |
| Multi-step workflows (p. 13) | no authority carried into the next step | each envelope evaluated independently |

## Status — what this is and is not

- A runnable **reference adapter**, not a product and not an endorsement by MAS or any SAFR
  contributor. Keys are **test keys**; institutions, agents and operators are fictitious.
- Escalating (rather than denying) an uncorroborated trace is a configurable policy choice.
- Not covered: human-review workflow after Escalate, data minimisation and retention, key
  management of a real deployment.

Licence: Apache-2.0 · Gravit Open Network Foundation, Zürich.
