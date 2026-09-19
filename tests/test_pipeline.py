import pytest

from agents import pipeline as p
from app.schemas import Finding

ALL = ["threat_intel", "log_analysis", "asset_identity"]


def make_fake(fail_agents=(), specialists=ALL):
    def fake(messages, model_cls, agent, incident_id="-", max_retries=1):
        if model_cls is p.TriagePlan:
            return p.TriagePlan(initial_severity="high", specialists=list(specialists),
                                rationale="test")
        if model_cls is p.SpecialistOutput:
            if agent in fail_agents:
                raise ValueError("boom")
            return p.SpecialistOutput(summary=f"{agent} ok", findings=[])
        return p.IncidentNarrative(summary="n", findings=[], contradictions=[])
    return fake


def test_full_run_collects_prefixed_evidence(monkeypatch):
    monkeypatch.setattr(p, "complete_json", make_fake())
    out = p.investigate_multi("INC-T")
    ids = {e["evidence_id"] for s in out["specialists"].values() for e in s["evidence"]}
    assert ids == {"TI-1", "LOG-1", "LOG-2", "ID-1"}
    assert out["issues"] == []


def test_one_specialist_failing_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(p, "complete_json", make_fake(fail_agents={"asset_identity"}))
    out = p.investigate_multi("INC-T")
    assert "asset_identity" not in out["specialists"]
    assert any("asset_identity failed" in i for i in out["issues"])
    assert out["narrative"]["summary"] == "n"


def test_all_specialists_failing_stops_the_workflow(monkeypatch):
    monkeypatch.setattr(p, "complete_json", make_fake(fail_agents=set(ALL)))
    with pytest.raises(RuntimeError):
        p.investigate_multi("INC-T")


def test_empty_triage_plan_falls_back_to_all_specialists(monkeypatch):
    monkeypatch.setattr(p, "complete_json", make_fake(specialists=[]))
    out = p.investigate_multi("INC-T")
    assert set(out["specialists"]) == set(ALL)


def test_grounding_flags_unknown_evidence():
    f = Finding(statement="x", kind="fact", evidence_ids=["EV-99"], confidence=0.5)
    assert p.check_grounding([f], {"LOG-1"}, "t")