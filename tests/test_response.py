import pytest
from pydantic import ValidationError

from agents import response as r
from agents.risk import RiskAssessment

RISK = RiskAssessment(score=11, severity="critical", reasons=["x"], requires_escalation=True)


def test_action_must_cite_evidence():
    with pytest.raises(ValidationError):
        r.ProposedAction(action_type="create_ticket", target="INC", justification="j",
                         evidence_ids=[])


def test_destructive_action_cannot_even_be_proposed():
    with pytest.raises(ValidationError):
        r.ProposedAction(action_type="delete_data", target="x", justification="j",
                         evidence_ids=["LOG-1"])


def test_actions_flow_through_policy(monkeypatch):
    plan = r.ResponsePlan(actions=[
        r.ProposedAction(action_type="create_ticket", target="INC-T",
                         justification="j", evidence_ids=["LOG-1"]),
        r.ProposedAction(action_type="disable_account", target="priya.sharma",
                         justification="j", evidence_ids=["LOG-1"]),
        r.ProposedAction(action_type="block_ip_simulation", target="203.0.113.10",
                         justification="j", evidence_ids=["LOG-99"]),
    ])
    monkeypatch.setattr(r, "complete_json", lambda *a, **k: plan)
    out = r.run_response({"summary": "s"}, RISK, "INC-T", {"LOG-1"})
    statuses = {q["action_type"]: q["status"] for q in out["requests"]}
    assert statuses == {"create_ticket": "executed", "disable_account": "pending_approval"}
    assert len(out["dropped"]) == 1