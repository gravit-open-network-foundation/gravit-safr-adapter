import copy

from safr_gravit.audit import verify_export
from scenarios.run import main


def test_scenarios_and_offline_audit(tmp_path, monkeypatch):
    assert main() == 0


def test_expected_outcomes():
    import json
    from pathlib import Path
    s = json.loads((Path(__file__).resolve().parent.parent / "results" / "summary.json").read_text())
    assert [r["outcome"] for r in s["scenarios"]] == [
        "Observe", "Auto-Execute", "Deny", "Deny", "Deny", "Escalate", "Escalate", "Escalate",
        "Escalate", "Escalate"]
    assert s["auditor_offline_check"]["ok"] and not s["auditor_check_of_tampered_copy"]["ok"]


def test_deleting_an_entry_is_detected():
    import json
    from pathlib import Path
    from safr_gravit.testkeys import pub
    export = json.loads((Path(__file__).resolve().parent.parent / "results" / "audit-export.json").read_text())
    cut = copy.deepcopy(export)
    del cut["entries"][2]
    assert not verify_export(cut, pub("example-bank-audit-log"))["ok"]
    assert not verify_export(export, pub("someone-else"))["ok"]
