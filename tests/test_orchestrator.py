from agents import orchestrator as o
from agents import pipeline as p
from agents.critic import CriticIssue, CriticVerdict


def fake_llm(messages, model_cls, agent, incident_id="-", max_retries=1):
    if model_cls is p.TriagePlan:
        return p.TriagePlan(initial_severity="high", rationale="t",
                            specialists=["threat_intel", "log_analysis", "asset_identity"])
    if model_cls is p.SpecialistOutput:
        return p.SpecialistOutput(summary="ok", findings=[])
    return p.IncidentNarrative(summary="n", findings=[], contradictions=[])


BLOCKING = CriticVerdict(verdict="fail", issues=[
    CriticIssue(source="rule", severity="blocking", problem="p", required_fix="f")])
PASS = CriticVerdict(verdict="pass", issues=[])


def test_failed_review_reworks_once_then_escalates(monkeypatch):
    monkeypatch.setattr(p, "complete_json", fake_llm)
    monkeypatch.setattr(o, "review", lambda *a, **k: BLOCKING)
    res = o.investigate_full("INC-T")
    assert res["reworks"] == 1 and res["status"] == "needs_human_review"
    assert "skipped" in res["response"]


def test_passing_review_goes_on_to_response(monkeypatch):
    monkeypatch.setattr(p, "complete_json", fake_llm)
    monkeypatch.setattr(o, "review", lambda *a, **k: PASS)
    monkeypatch.setattr(o, "run_response",
                        lambda *a, **k: {"plan": {}, "requests": [], "dropped": []})
    res = o.investigate_full("INC-T")
    assert res["reworks"] == 0 and res["status"] == "complete"
    assert res["risk"]["severity"] == "critical"