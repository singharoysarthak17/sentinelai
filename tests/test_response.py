import pytest
from pydantic import ValidationError

from agents import response as r
from agents.risk import RiskAssessment

RISK = RiskAssessment(score=11, severity="critical", reasons=["x"], requires_escalation=True)
CHUNKS = [{"chunk_id": "POL-003#2", "doc_id": "POL-003", "title": "Privileged Access Policy",
           "text": "Any change to a privileged account requires approval.", "score": 5.0}]


def act(action_type, target, evidence, policy=()):
    return r.ProposedAction(action_type=action_type, target=target, justification="j",
                            evidence_ids=list(evidence), policy_ids=list(policy))


def run_with(monkeypatch, actions):
    monkeypatch.setattr(r, "_retrieve_policy", lambda *a, **k: CHUNKS)
    monkeypatch.setattr(r, "complete_json", lambda *a, **k: r.ResponsePlan(actions=actions))
    return r.run_response({"summary": "s"}, RISK, "INC-T", {"LOG-1"})


def test_action_must_cite_evidence():
    with pytest.raises(ValidationError):
        act("create_ticket", "INC", [])


def test_destructive_action_cannot_even_be_proposed():
    with pytest.raises(ValidationError):
        act("delete_data", "x", ["LOG-1"])


def test_actions_flow_through_policy(monkeypatch):
    out = run_with(monkeypatch, [
        act("create_ticket", "INC-T", ["LOG-1"]),
        act("disable_account", "priya.sharma", ["LOG-1"], ["POL-003#2"]),
        act("block_ip_simulation", "203.0.113.10", ["LOG-99"]),
    ])
    statuses = {q["action_type"]: q["status"] for q in out["requests"]}
    assert statuses == {"create_ticket": "executed", "disable_account": "pending_approval"}
    assert len(out["dropped"]) == 1


def test_high_impact_action_without_policy_citation_is_dropped(monkeypatch):
    out = run_with(monkeypatch, [act("disable_account", "priya.sharma", ["LOG-1"])])
    assert out["requests"] == []
    assert "policy" in out["dropped"][0]["reason"]


def test_unknown_policy_chunk_is_dropped(monkeypatch):
    out = run_with(monkeypatch, [act("disable_account", "priya.sharma", ["LOG-1"], ["POL-999#1"])])
    assert out["requests"] == [] and len(out["dropped"]) == 1


def test_retrieval_returns_only_visible_trusted_policy():
    ids = {c["chunk_id"] for c in r._retrieve_policy("INC-T", "analyst")}
    assert any(i.startswith(("POL-001", "POL-003")) for i in ids)
    assert not any(i.startswith(("POL-005", "POL-006")) for i in ids)